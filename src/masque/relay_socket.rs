// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! MASQUE Relay Socket
//!
//! A virtual UDP socket backed entirely by a MASQUE relay tunnel.
//!
//! Implements [`AsyncUdpSocket`] so it can back a standalone Quinn
//! endpoint that accepts connections arriving through the relay.  The
//! node's **main** endpoint keeps its original UDP socket and is never
//! touched — this socket powers a **second** endpoint that provides an
//! additional inbound path.
//!
//! ## Routing
//!
//! - **Outgoing** → encoded as length-prefixed
//!   [`UncompressedDatagram`]s and written to the relay QUIC stream.
//! - **Incoming** → read from the relay QUIC stream, decoded, and
//!   queued for Quinn's `poll_recv`.

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
/// [`MasqueRelaySocket`] with the additional context it needs.
pub struct RawRelayStreams {
    /// Send half of the relay QUIC stream (length-prefixed datagrams).
    pub send_stream: crate::high_level::SendStream,
    /// Receive half of the relay QUIC stream.
    pub recv_stream: crate::high_level::RecvStream,
}

/// A virtual UDP socket backed entirely by a MASQUE relay tunnel.
///
/// All traffic — both outgoing and incoming — flows through the relay
/// QUIC stream.  This socket is intended for a **second** Quinn endpoint
/// dedicated to relay traffic, leaving the main endpoint and its
/// original UDP socket completely untouched.
pub struct MasqueRelaySocket {
    /// The relay's public address (returned as our local address).
    relay_public_addr: SocketAddr,
    /// Queue of received packets (payload, source_addr).
    recv_queue: std::sync::Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    /// Waker to notify when new packets arrive.
    recv_waker: std::sync::Mutex<Option<Waker>>,
    /// Channel for outbound packets (written to the relay stream by
    /// the background write task).
    send_tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
    /// The original socket is kept alive so the relay connection's own
    /// QUIC traffic (keepalives, ACKs, stream data) continues to flow
    /// directly.  Without this reference the OS may reclaim the socket.
    _original_socket: Arc<dyn AsyncUdpSocket>,
}

impl fmt::Debug for MasqueRelaySocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueRelaySocket")
            .field("relay_public_addr", &self.relay_public_addr)
            .field(
                "recv_queue_len",
                &self.recv_queue.lock().map(|q| q.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl MasqueRelaySocket {
    /// Create a new tunnel-only relay socket.
    ///
    /// All I/O flows through the relay QUIC stream.  `original_socket`
    /// is held alive (but not used for I/O) to prevent the OS from
    /// reclaiming the underlying file descriptor while the relay
    /// connection's own QUIC traffic still needs it.
    ///
    /// Spawns two background tasks:
    /// - A reader that decodes length-prefixed frames from
    ///   `recv_stream` and queues them for [`poll_recv`].
    /// - A writer that drains the `send_tx` channel and writes
    ///   length-prefixed frames to `send_stream`.
    pub fn new(
        mut send_stream: crate::high_level::SendStream,
        mut recv_stream: crate::high_level::RecvStream,
        relay_public_addr: SocketAddr,
        _relay_server_addr: SocketAddr,
        original_socket: Arc<dyn AsyncUdpSocket>,
    ) -> Arc<Self> {
        let (send_tx, mut send_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();

        let socket = Arc::new(Self {
            relay_public_addr,
            recv_queue: std::sync::Mutex::new(VecDeque::new()),
            recv_waker: std::sync::Mutex::new(None),
            send_tx,
            _original_socket: original_socket,
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
                // Safety cap — same as relay_server::MAX_RELAY_FRAME.
                if frame_len > 512 * 1024 {
                    tracing::warn!(frame_len, "MasqueRelaySocket: corrupt frame length");
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
        // The tunnel is always writable (writes go to an unbounded
        // mpsc), so the poller just returns Ready immediately.
        Box::pin(TunnelPoller)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // When Quinn uses GSO (Generic Segmentation Offload),
        // transmit.contents contains multiple concatenated QUIC packets
        // of `segment_size` bytes.  Each segment must be sent as its
        // own tunnel frame — the relay server has a per-frame size
        // limit and cannot handle the entire batch as one.
        if let Some(segment_size) = transmit.segment_size {
            for chunk in transmit.contents.chunks(segment_size) {
                let datagram = UncompressedDatagram::new(
                    VarInt::from_u32(0),
                    transmit.destination,
                    Bytes::copy_from_slice(chunk),
                );
                self.send_tx.send(datagram.encode()).map_err(|_| {
                    io::Error::new(io::ErrorKind::ConnectionAborted, "relay stream closed")
                })?;
            }
            return Ok(());
        }

        let datagram = UncompressedDatagram::new(
            VarInt::from_u32(0),
            transmit.destination,
            Bytes::copy_from_slice(transmit.contents),
        );
        self.send_tx
            .send(datagram.encode())
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

        // Register the waker BEFORE checking the queue to avoid a race
        // with the background reader task.  Without this ordering:
        //   1. poll_recv checks queue → empty
        //   2. background task pushes packet + tries to wake → no waker
        //   3. poll_recv stores waker → returns Pending
        //   4. packet sits undelivered until the next arrival
        // Registering first means the background task will always see a
        // waker if it pushes between our registration and queue check.
        // Spurious wakes are harmless — Quinn will re-poll and find
        // nothing.
        if let Ok(mut waker) = self.recv_waker.lock() {
            *waker = Some(cx.waker().clone());
        }

        let capacity = bufs.len().min(meta.len());
        let mut filled = 0;

        if let Ok(mut queue) = self.recv_queue.lock() {
            while filled < capacity {
                let Some((payload, source)) = queue.pop_front() else {
                    break;
                };
                if payload.len() > bufs[filled].len() {
                    tracing::warn!(
                        payload_len = payload.len(),
                        buf_len = bufs[filled].len(),
                        "MasqueRelaySocket: payload exceeds receive buffer; dropping packet"
                    );
                    continue;
                }
                let len = payload.len();
                bufs[filled][..len].copy_from_slice(&payload);

                let mut recv_meta = RecvMeta::default();
                recv_meta.len = len;
                recv_meta.stride = len;
                recv_meta.addr = source;
                recv_meta.ecn = None;
                recv_meta.dst_ip = None;
                meta[filled] = recv_meta;

                tracing::trace!(
                    source = %source,
                    len,
                    "RELAY_TUNNEL: recv from tunnel queue"
                );

                filled += 1;
            }
        }

        if filled > 0 {
            return Poll::Ready(Ok(filled));
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

/// Poller for the tunnel socket.
///
/// The tunnel is always writable (writes go to an unbounded mpsc
/// channel), so this immediately returns `Ready`.
#[derive(Debug)]
struct TunnelPoller;

impl UdpPoller for TunnelPoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
