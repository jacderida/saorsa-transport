// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! MASQUE Relay Socket
//!
//! A virtual UDP socket that routes QUIC packets through a MASQUE relay
//! via a persistent QUIC stream (length-prefixed framing).
//!
//! Implements [`AsyncUdpSocket`] so it can be plugged into a Quinn endpoint
//! as a transparent replacement for a real UDP socket.
//!
//! ## Relay-server bypass
//!
//! When constructed with [`MasqueRelaySocket::new`], the socket also receives
//! the relay server's address and the original UDP socket. Packets destined
//! for the relay server bypass the tunnel and go directly through the
//! original socket, breaking the circular dependency where the relay
//! tunnel's own QUIC connection would otherwise route through itself.

use bytes::Bytes;
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use quinn_udp::{RecvMeta, Transmit};

use crate::VarInt;
use crate::high_level::{AsyncUdpSocket, UdpPoller};
use crate::masque::UncompressedDatagram;

/// Raw QUIC streams from a relay session, before socket construction.
///
/// Returned by `establish_relay_session` so the caller can construct a
/// [`MasqueRelaySocket`] with the additional context it needs (e.g. the
/// relay-server bypass socket).
pub struct RawRelayStreams {
    /// Send half of the relay QUIC stream (length-prefixed datagrams).
    pub send_stream: crate::high_level::SendStream,
    /// Receive half of the relay QUIC stream.
    pub recv_stream: crate::high_level::RecvStream,
}

/// A virtual UDP socket that tunnels packets through a MASQUE relay
/// via a persistent QUIC stream with length-prefixed framing.
///
/// Packets destined for the relay server itself bypass the tunnel and
/// are sent directly through the original UDP socket, preventing the
/// relay connection's own QUIC traffic from looping through its own
/// tunnel.
pub struct MasqueRelaySocket {
    /// The relay's public address (returned as our local address).
    relay_public_addr: SocketAddr,
    /// Queue of received packets (payload, source_addr).
    recv_queue: std::sync::Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    /// Waker to notify when new packets arrive.
    recv_waker: std::sync::Mutex<Option<Waker>>,
    /// Channel for outbound packets (written to the relay stream by background task).
    send_tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
    /// The relay server's address — traffic to this address bypasses the
    /// tunnel and goes through `original_socket` instead.
    relay_server_addr: SocketAddr,
    /// The pre-rebind UDP socket kept alive for the relay connection's own
    /// QUIC traffic.
    original_socket: Arc<dyn AsyncUdpSocket>,
}

impl fmt::Debug for MasqueRelaySocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueRelaySocket")
            .field("relay_public_addr", &self.relay_public_addr)
            .field("relay_server_addr", &self.relay_server_addr)
            .field(
                "recv_queue_len",
                &self.recv_queue.lock().map(|q| q.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl MasqueRelaySocket {
    /// Create a new stream-based relay socket with relay-server bypass.
    ///
    /// `relay_server_addr` is the address of the relay server (the peer
    /// carrying the MASQUE tunnel). `original_socket` is the endpoint's
    /// pre-rebind UDP socket. Together they allow the relay connection's
    /// own QUIC traffic to bypass the tunnel.
    ///
    /// Spawns two background tasks:
    /// - Read from `recv_stream`, decode frames, queue for `poll_recv`
    /// - Read from `send_tx` channel, write length-prefixed frames to `send_stream`
    pub fn new(
        mut send_stream: crate::high_level::SendStream,
        mut recv_stream: crate::high_level::RecvStream,
        relay_public_addr: SocketAddr,
        relay_server_addr: SocketAddr,
        original_socket: Arc<dyn AsyncUdpSocket>,
    ) -> Arc<Self> {
        let (send_tx, mut send_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();

        let socket = Arc::new(Self {
            relay_public_addr,
            recv_queue: std::sync::Mutex::new(VecDeque::new()),
            recv_waker: std::sync::Mutex::new(None),
            send_tx,
            relay_server_addr,
            original_socket,
        });

        // Background task: read length-prefixed frames from relay stream → queue
        let socket_ref = Arc::clone(&socket);
        tokio::spawn(async move {
            loop {
                // Read 4-byte length prefix
                let mut len_buf = [0u8; 4];
                if let Err(e) = recv_stream.read_exact(&mut len_buf).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream read error (length)");
                    break;
                }
                let frame_len = u32::from_be_bytes(len_buf) as usize;
                if frame_len > 65536 {
                    tracing::warn!(frame_len, "MasqueRelaySocket: oversized frame");
                    break;
                }

                // Read frame data
                let mut frame_buf = vec![0u8; frame_len];
                if let Err(e) = recv_stream.read_exact(&mut frame_buf).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream read error (data)");
                    break;
                }

                // Decode as UncompressedDatagram
                let mut cursor = Bytes::from(frame_buf);
                match UncompressedDatagram::decode(&mut cursor) {
                    Ok(datagram) => {
                        let payload = datagram.payload.to_vec();
                        let source = datagram.target; // "target" in datagram = source from relay's perspective

                        if let Ok(mut queue) = socket_ref.recv_queue.lock() {
                            queue.push_back((payload, source));
                        }
                        if let Ok(mut waker) = socket_ref.recv_waker.lock() {
                            if let Some(w) = waker.take() {
                                w.wake();
                            }
                        }
                    }
                    Err(_) => {
                        tracing::trace!("MasqueRelaySocket: failed to decode frame");
                    }
                }
            }

            // Wake pending recv on stream close
            if let Ok(mut waker) = socket_ref.recv_waker.lock() {
                if let Some(w) = waker.take() {
                    w.wake();
                }
            }
        });

        // Background task: write queued outbound packets to relay stream
        tokio::spawn(async move {
            while let Some(encoded) = send_rx.recv().await {
                let frame_len = encoded.len() as u32;
                if let Err(e) = send_stream.write_all(&frame_len.to_be_bytes()).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream write error (length)");
                    break;
                }
                if let Err(e) = send_stream.write_all(&encoded).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream write error (data)");
                    break;
                }
            }
        });

        socket
    }
}

impl AsyncUdpSocket for MasqueRelaySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(RelayPoller {
            original: self.original_socket.clone().create_io_poller(),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // Bypass the tunnel for traffic destined to the relay server itself.
        // The relay connection's own QUIC packets (keepalives, ACKs, stream
        // data carrying the tunnel) must go directly on the original socket;
        // routing them through the tunnel would create a circular dependency.
        if transmit.destination == self.relay_server_addr {
            return self.original_socket.try_send(transmit);
        }

        let datagram = UncompressedDatagram::new(
            VarInt::from_u32(0),
            transmit.destination,
            Bytes::copy_from_slice(transmit.contents),
        );
        let encoded = datagram.encode();

        self.send_tx
            .send(encoded)
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionAborted, "relay stream closed"))
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Priority 1: drain packets that arrived through the relay tunnel.
        if let Ok(mut queue) = self.recv_queue.lock() {
            if let Some((payload, source)) = queue.pop_front() {
                // Drop oversized payloads rather than truncating — a truncated
                // QUIC packet fails MAC verification and stalls the connection.
                if payload.len() > bufs[0].len() {
                    tracing::warn!(
                        payload_len = payload.len(),
                        buf_len = bufs[0].len(),
                        "MasqueRelaySocket: payload exceeds receive buffer; dropping packet"
                    );
                    return Poll::Ready(Ok(0));
                }
                let len = payload.len();
                bufs[0][..len].copy_from_slice(&payload);

                let mut recv_meta = RecvMeta::default();
                recv_meta.len = len;
                recv_meta.stride = len;
                recv_meta.addr = source;
                recv_meta.ecn = None;
                recv_meta.dst_ip = None;
                meta[0] = recv_meta;

                return Poll::Ready(Ok(1));
            }
        }

        // Priority 2: check the original socket for relay-server traffic
        // (QUIC packets from the relay server's connection).
        match self.original_socket.poll_recv(cx, bufs, meta) {
            Poll::Ready(result) => return Poll::Ready(result),
            Poll::Pending => {}
        }

        // Neither source has data — register waker for the tunnel queue.
        // (The original socket already registered the waker in its
        // poll_recv above, so we'll be woken for either source.)
        if let Ok(mut waker) = self.recv_waker.lock() {
            *waker = Some(cx.waker().clone());
        }

        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.relay_public_addr)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

/// Poller that delegates to the original socket's poller.
///
/// The relay tunnel is always writable (writes go to an unbounded mpsc),
/// but the original socket may need to register a write waker for its
/// kernel buffer. We use the original socket's poller to cover both.
#[derive(Debug)]
struct RelayPoller {
    original: Pin<Box<dyn UdpPoller>>,
}

impl UdpPoller for RelayPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.original.as_mut().poll_writable(cx)
    }
}
