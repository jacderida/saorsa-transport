// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! MASQUE Relay Server
//!
//! Implements a MASQUE CONNECT-UDP Bind relay server that any peer can run.
//! Per ADR-004 (Symmetric P2P), all nodes participate in relaying with
//! resource budgets to prevent abuse.
//!
//! # Overview
//!
//! The relay server manages multiple [`RelaySession`]s, one per connected client.
//! It handles:
//! - Session creation and lifecycle management
//! - Authentication via ML-DSA-65 (reusing existing infrastructure)
//! - Rate limiting and bandwidth budgets
//! - Datagram forwarding between clients and targets
//!
//! # Example
//!
//! ```rust,ignore
//! use saorsa_transport::masque::relay_server::{MasqueRelayServer, MasqueRelayConfig};
//! use std::net::SocketAddr;
//!
//! let config = MasqueRelayConfig::default();
//! let public_addr = "203.0.113.50:9000".parse().unwrap();
//! let server = MasqueRelayServer::new(config, public_addr);
//! ```

use bytes::Bytes;
use parking_lot::RwLock as ParkingRwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify, RwLock};
use tokio_util::sync::CancellationToken;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
use std::os::unix::io::AsRawFd;

use crate::VarInt;
use crate::high_level::Connection as QuicConnection;
use crate::masque::ip_policy::IpPolicy;
use crate::masque::tunnel_control::{CONTROL_FRAME_MARKER, TunnelControlFrame};
use crate::masque::{
    Capsule, ConnectUdpRequest, ConnectUdpResponse, Datagram, RelayPeerId, RelaySession,
    RelaySessionConfig, RelaySessionState, UncompressedDatagram,
};
use crate::relay::error::{RelayError, RelayResult, SessionErrorKind};
use crate::upnp::{UpnpConfig, UpnpMappingService};

/// Interval at which both sides of a relay stream send a zero-length
/// keepalive frame.  Keeps the NAT conntrack entry alive (default
/// `nf_conntrack_udp_timeout_stream` is 120 s on Linux) and prevents
/// the QUIC idle timeout from firing on the underlying connection.
const RELAY_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const RELAY_STREAM_BATCH_MAX_FRAMES: usize = 64;
const RELAY_STREAM_BATCH_MAX_BYTES: usize = 64 * 1024;

/// Capacity of the bounded channel between the UDP reader task and the
/// stream writer task in Direction 1 (external → NATted node).  Sized
/// to absorb a full max-message-size burst (~4 MB / ~1200 bytes per
/// QUIC packet ≈ 3500 packets) without the reader stalling.  Acts as a
/// userspace buffer that replaces the tiny kernel UDP receive buffer
/// (208 KB default on Linux, which holds only ~170 packets).
const RELAY_FORWARD_CHANNEL_CAPACITY: usize = 8192;

/// Minimum interval between relay-reservation INFO summary lines (ADR-011).
/// Per-event reservation detail is logged at DEBUG to keep production log
/// volume low; one summary per relay per interval is enough to confirm the
/// feature is working (reclaim hits climbing, reservation pool size).
const RELAY_RESERVATION_SUMMARY_INTERVAL_MS: u64 = 5 * 60 * 1000; // 5 minutes

/// Number of mutex stripes used to serialize concurrent CONNECTs from the same
/// authenticated identity (ADR-011). A peer maps to a stripe by the first byte
/// of its fingerprint, so same-identity CONNECTs always take the same lock while
/// memory stays bounded (no per-peer map that grows without limit).
const RELAY_PEER_LOCK_STRIPES: usize = 256;

/// Suggested PMTU sent to the relay-client when the egress UDP send
/// fails with `EMSGSIZE`.  Picked to be QUIC's mandatory minimum
/// datagram size (1200 bytes), which any conformant path must carry.
/// Real path MTUs are usually higher; the relay-client's Quinn DPLPMTUD
/// can probe upward from there once it lowers to this floor.
const PMTU_FALLBACK_HINT: u16 = 1200;

/// Set the local "don't fragment" bit on a freshly-bound UDP socket so
/// that oversized [`UdpSocket::send_to`] calls fail with `EMSGSIZE`
/// instead of being silently fragmented at the IP layer.  Without this
/// the kernel happily fragments the egress datagram, the user-side
/// path then drops the fragments (most home NATs / routers refuse
/// fragmented UDP), and the relay-server cannot tell that the path
/// rejected the packet — which is exactly the false-success that lets
/// Quinn's PMTU estimate stay too high.
///
/// Returns the underlying I/O error so the caller can decide whether
/// to bail or proceed with default fragmentation behaviour.
#[cfg(target_os = "linux")]
fn set_dont_fragment(socket: &UdpSocket) -> std::io::Result<()> {
    let fd = socket.as_raw_fd();

    // Linux: opt into kernel-level PMTU discovery.  IP_PMTUDISC_DO
    // forces DF=1 on every outbound IPv4 datagram and surfaces
    // EMSGSIZE on the send_to that exceeds the path MTU.
    let v4_val: libc::c_int = libc::IP_PMTUDISC_DO;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            std::ptr::from_ref(&v4_val).cast::<libc::c_void>(),
            std::mem::size_of_val(&v4_val) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Same for IPv6 — best effort: the socket may be v4-only, in
    // which case the setsockopt fails with ENOPROTOOPT and that's
    // fine.  We deliberately ignore the result to keep the v4 path
    // working on dual-stack-incapable kernels.
    let v6_val: libc::c_int = libc::IPV6_PMTUDISC_DO;
    let _ = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            std::ptr::from_ref(&v6_val).cast::<libc::c_void>(),
            std::mem::size_of_val(&v6_val) as libc::socklen_t,
        )
    };

    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn set_dont_fragment(socket: &UdpSocket) -> std::io::Result<()> {
    // BSD-derived kernels expose a simple boolean IP_DONTFRAG /
    // IPV6_DONTFRAG.  Behaviour matches Linux's IP_PMTUDISC_DO: DF=1
    // on outbound, EMSGSIZE on too-big.
    let fd = socket.as_raw_fd();
    let on: libc::c_int = 1;

    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_DONTFRAG,
            std::ptr::from_ref(&on).cast::<libc::c_void>(),
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let _ = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_DONTFRAG,
            std::ptr::from_ref(&on).cast::<libc::c_void>(),
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };

    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
fn set_dont_fragment(_socket: &UdpSocket) -> std::io::Result<()> {
    // Other platforms: best-effort no-op.  PMTU discovery falls back
    // to default kernel behaviour (silent fragmentation) and the
    // tunnel-level PMTU control frame loop never fires.
    Ok(())
}

/// Did this `send_to` failure mean "datagram too large for path"?
/// Linux returns `EMSGSIZE` (errno 90); BSD returns `EMSGSIZE` as well.
/// Treated as the only signal that warrants emitting a PMTU control
/// frame back through the tunnel.
#[cfg(unix)]
fn is_message_too_large(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::EMSGSIZE)
}

/// Non-Unix targets do not link `libc`, and the corresponding
/// `set_dont_fragment` is a best-effort no-op there. Mirror that
/// behaviour: never claim a send error is PMTU-related, so the
/// tunnel-level PMTU control frame loop simply does not fire and we
/// fall back to the kernel's default fragmentation behaviour.
#[cfg(not(unix))]
fn is_message_too_large(_err: &std::io::Error) -> bool {
    false
}

/// Item carried over the bounded channel between the UDP reader task
/// and the QUIC stream writer task in [`MasqueRelayServer::run_stream_forwarding_loop`].
///
/// Both data frames (UDP arriving on the bound socket) and control
/// frames (out-of-band tunnel-level signals such as PMTU updates)
/// share the writer task so frame ordering is preserved and the
/// keepalive timer treats both equally.
enum WriterItem {
    /// A length-prefixed [`UncompressedDatagram`]-encoded payload
    /// that originated from a Direction-1 UDP recv.
    Data(Bytes),
    /// A control frame body (everything after the
    /// `[CONTROL_FRAME_MARKER][body_len]` header).  The writer
    /// prepends the header before sending.
    Control(Bytes),
}

fn append_relay_frame(out: &mut Vec<u8>, encoded: &Bytes) {
    let frame_len = encoded.len() as u32;
    out.extend_from_slice(&frame_len.to_be_bytes());
    out.extend_from_slice(encoded);
}

fn append_control_frame(out: &mut Vec<u8>, body: &Bytes) {
    let body_len = body.len() as u32;
    out.extend_from_slice(&CONTROL_FRAME_MARKER.to_be_bytes());
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(body);
}

/// Configuration for the MASQUE relay server
#[derive(Debug, Clone)]
pub struct MasqueRelayConfig {
    /// Maximum concurrent sessions
    pub max_sessions: usize,
    /// Session configuration template
    pub session_config: RelaySessionConfig,
    /// Cleanup interval for expired sessions
    pub cleanup_interval: Duration,
    /// Global bandwidth limit in bytes per second
    pub global_bandwidth_limit: u64,
    /// Enable authentication requirement
    pub require_authentication: bool,
    /// Freshness window for a stable-port reservation (ADR-011): after the
    /// session using it ends, a reconnecting authenticated peer reclaims the port
    /// only if it returns within this window. Expiry is **lazy** — the TTL is
    /// checked when the peer reconnects (a stale reservation is discarded and a
    /// fresh port bound), not by a background sweeper. Idle reservations from
    /// peers that never return are bounded instead by `max_reservations` (LRU
    /// eviction); `cleanup_expired_reservations()` can be called to sweep them
    /// proactively but is not wired to a timer.
    pub reservation_ttl: Duration,
    /// Maximum number of idle stable-port reservations held at once. When the
    /// cap is reached the least-recently-released reservation is evicted (its
    /// port freed) to bound socket/fd/memory use under churn.
    pub max_reservations: usize,
}

impl Default for MasqueRelayConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            session_config: RelaySessionConfig::default(),
            cleanup_interval: Duration::from_secs(60),
            global_bandwidth_limit: 100 * 1024 * 1024, // 100 MB/s
            require_authentication: true,
            reservation_ttl: Duration::from_secs(600), // 10 minutes
            max_reservations: 1024,
        }
    }
}

/// Statistics for the relay server
#[derive(Debug, Default)]
pub struct MasqueRelayStats {
    /// Total sessions created
    pub sessions_created: AtomicU64,
    /// Currently active sessions
    pub active_sessions: AtomicU64,
    /// Sessions terminated
    pub sessions_terminated: AtomicU64,
    /// Total bytes relayed
    pub bytes_relayed: AtomicU64,
    /// Total datagrams forwarded
    pub datagrams_forwarded: AtomicU64,
    /// Authentication failures
    pub auth_failures: AtomicU64,
    /// Rate limit rejections
    pub rate_limit_rejections: AtomicU64,
}

impl MasqueRelayStats {
    /// Create new statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new session
    pub fn record_session_created(&self) {
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record session termination
    pub fn record_session_terminated(&self) {
        self.sessions_terminated.fetch_add(1, Ordering::Relaxed);
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record bytes relayed
    pub fn record_bytes(&self, bytes: u64) {
        self.bytes_relayed.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a datagram forwarded
    pub fn record_datagram(&self) {
        self.datagrams_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Record authentication failure
    pub fn record_auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record rate limit rejection
    pub fn record_rate_limit(&self) {
        self.rate_limit_rejections.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current active session count
    pub fn current_active_sessions(&self) -> u64 {
        self.active_sessions.load(Ordering::Relaxed)
    }

    /// Get total bytes relayed
    pub fn total_bytes_relayed(&self) -> u64 {
        self.bytes_relayed.load(Ordering::Relaxed)
    }
}

/// Pending outbound datagram to be sent
#[derive(Debug, Clone)]
pub struct OutboundDatagram {
    /// Target address for the datagram
    pub target: SocketAddr,
    /// The datagram payload
    pub payload: Bytes,
    /// Session ID this datagram belongs to
    pub session_id: u64,
}

/// Result from processing an incoming datagram
#[derive(Debug)]
pub enum DatagramResult {
    /// Datagram should be forwarded to target
    Forward(OutboundDatagram),
    /// Datagram handled internally (e.g., to client via relay)
    Internal,
    /// Session not found
    SessionNotFound,
    /// Error processing datagram
    Error(RelayError),
}

/// Full 64-hex rendering of a 32-byte peer fingerprint. Used on
/// reservation-lifecycle DEBUG lines (V2-568 measurement campaign) so the
/// create→reclaim lifecycle and identity churn (same client IP, changing
/// fingerprint) can be correlated on the whole identity rather than an 8-byte
/// prefix.
fn full_peer_hex(id: &RelayPeerId) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in &id[..] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Render an optional client address for a structured `client` log field,
/// falling back to an empty string when the closing session had no recorded
/// client address (keeps the field present and greppable in ES).
fn client_field(addr: Option<SocketAddr>) -> String {
    addr.map(|a| a.to_string()).unwrap_or_default()
}

/// Per-session control handle for the stream-forwarding loop (ADR-011).
///
/// `cancel` lets `close_session` stop a still-live forwarding loop — e.g. a
/// same-identity handover — rather than leaving an untracked data plane running
/// after the session is removed. `done` is signalled by the loop once it has
/// aborted its reader/writer tasks and released the socket, so a handover waits
/// until the old loop has fully quiesced before the port is reused.
#[derive(Clone)]
struct ForwardingControl {
    cancel: CancellationToken,
    done: Arc<Notify>,
}

/// A retained stable relay-port reservation (ADR-011).
///
/// Created when a relayed peer's session ends: instead of dropping the bound
/// UDP socket (which frees the OS-assigned port), the socket is moved here and
/// kept alive so the *same* port can be handed back when that peer — identified
/// by its authenticated ML-DSA fingerprint — reconnects. Holding the socket
/// makes reuse conflict-free for the lease window. Bounded by TTL and LRU cap.
struct Reservation {
    /// The stable public port retained for the peer.
    port: u16,
    /// The bound UDP socket, kept alive so the kernel cannot reassign the port
    /// while the reservation is held.
    udp_socket: Arc<UdpSocket>,
    /// UPnP mapping for the retained port, kept alive alongside the socket so
    /// NAT forwarding survives the lease. Shut down explicitly on release.
    upnp: Option<UpnpMappingService>,
    /// The relay-client socket address of the session that created this
    /// reservation, recorded so the create→reclaim lifecycle can be tied by
    /// client IP and identity churn detected (V2-568). `None` only if the
    /// closing session had no recorded client address.
    client: Option<SocketAddr>,
    /// When the session using this port was released — the start of the lease,
    /// used for TTL expiry and least-recently-released eviction.
    released_at: Instant,
}

/// MASQUE Relay Server
///
/// Manages multiple relay sessions and coordinates datagram forwarding
/// between clients and their targets.
///
/// # Dual-Stack Support
///
/// The relay server can be created with dual-stack support using [`Self::new_dual_stack`],
/// which allows bridging traffic between IPv4 and IPv6 networks. This enables
/// nodes that only have one IP version to communicate with nodes on the other version.
pub struct MasqueRelayServer {
    /// Server configuration
    config: MasqueRelayConfig,
    /// Primary public address advertised to clients.
    ///
    /// Interior-mutable: initialized with the bind address at construction,
    /// then updated to the real external IP when `OBSERVED_ADDRESS` frames
    /// arrive. Uses `parking_lot::RwLock` (not tokio) because all access is
    /// synchronous.
    public_address: ParkingRwLock<SocketAddr>,
    /// Secondary public address (other IP version for dual-stack)
    secondary_address: Option<SocketAddr>,
    /// Active sessions by session ID
    sessions: RwLock<HashMap<u64, RelaySession>>,
    /// Mapping from client address to session ID
    client_to_session: RwLock<HashMap<SocketAddr, u64>>,
    /// Next session ID
    next_session_id: AtomicU64,
    /// Server statistics
    stats: Arc<MasqueRelayStats>,
    /// Server start time
    started_at: Instant,
    /// Bridged connection count (IPv4↔IPv6)
    bridged_connections: AtomicU64,
    /// ADR-011 reservation activity counters (cumulative), surfaced in a
    /// rate-limited INFO summary so production gets a low-volume "feature is
    /// working" signal while per-event detail stays at DEBUG.
    reservation_hits: AtomicU64,
    reservation_misses: AtomicU64,
    reservations_created: AtomicU64,
    reservations_expired: AtomicU64,
    reservations_evicted: AtomicU64,
    /// Epoch-millis of the last reservation summary emit (rate-limit gate).
    last_reservation_summary_ms: AtomicU64,
    /// Control handles for currently-live stream-forwarding loops, keyed by
    /// session id. Lets `close_session` cancel and await a live loop (so a
    /// same-identity handover stops the old data plane before reusing the port)
    /// and serves as a claim so a session never gets two concurrent loops. A
    /// loop registers here before touching its socket and deregisters only after
    /// aborting its reader/writer tasks, so the socket is exclusively owned by the
    /// time it can be leased.
    forwarding: RwLock<HashMap<u64, ForwardingControl>>,
    /// Mutex stripes serializing concurrent CONNECTs from the same authenticated
    /// identity (ADR-011), indexed by the first fingerprint byte. Length is
    /// `RELAY_PEER_LOCK_STRIPES`.
    peer_locks: Vec<Mutex<()>>,
    /// Whether this node is willing to serve as a relay for private peers.
    ///
    /// Set to `false` by the ADR-014 reachability classifier when the node
    /// determines it is itself private (not publicly reachable). Private
    /// nodes reject incoming relay reservation requests since they cannot
    /// forward traffic from the public internet.
    ///
    /// Defaults to `true` so nodes are relay-capable unless the classifier
    /// explicitly disables it.
    relay_serving_enabled: AtomicBool,
    /// UPnP port mappings for relay-allocated sockets, keyed by session ID.
    /// Each relay session binds a random ephemeral port; this mapping asks
    /// the local IGD gateway (if any) to forward that port from the public
    /// side so relay-forwarded traffic can reach it through a NAT.
    upnp_mappings: RwLock<HashMap<u64, UpnpMappingService>>,
    /// Retained stable-port reservations keyed by the relayed peer's
    /// authenticated ML-DSA fingerprint (ADR-011). Populated on session close
    /// for authenticated peers; consumed when the same peer reconnects, or
    /// dropped by TTL/LRU eviction.
    reservations: RwLock<HashMap<RelayPeerId, Reservation>>,
    /// Optional IP-diversity policy shared with the node's relay-client half.
    /// When set, the server refuses inbound clients whose source IP matches
    /// one of our current upstream relays (see [`IpPolicy`]).
    ip_policy: Option<Arc<IpPolicy>>,
}

impl std::fmt::Debug for MasqueRelayServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueRelayServer")
            .field("public_address", &*self.public_address.read())
            .field("secondary_address", &self.secondary_address)
            .field("started_at", &self.started_at)
            .finish_non_exhaustive()
    }
}

impl MasqueRelayServer {
    /// Create a new MASQUE relay server with a single IP version
    pub fn new(config: MasqueRelayConfig, public_address: SocketAddr) -> Self {
        Self {
            config,
            public_address: ParkingRwLock::new(public_address),
            secondary_address: None,
            relay_serving_enabled: AtomicBool::new(true),
            sessions: RwLock::new(HashMap::new()),
            client_to_session: RwLock::new(HashMap::new()),
            next_session_id: AtomicU64::new(1),
            stats: Arc::new(MasqueRelayStats::new()),
            started_at: Instant::now(),
            bridged_connections: AtomicU64::new(0),
            reservation_hits: AtomicU64::new(0),
            reservation_misses: AtomicU64::new(0),
            reservations_created: AtomicU64::new(0),
            reservations_expired: AtomicU64::new(0),
            reservations_evicted: AtomicU64::new(0),
            last_reservation_summary_ms: AtomicU64::new(0),
            upnp_mappings: RwLock::new(HashMap::new()),
            reservations: RwLock::new(HashMap::new()),
            forwarding: RwLock::new(HashMap::new()),
            peer_locks: (0..RELAY_PEER_LOCK_STRIPES)
                .map(|_| Mutex::new(()))
                .collect(),
            ip_policy: None,
        }
    }

    /// Install a shared [`IpPolicy`]. Should be the same handle passed to the
    /// node's [`super::RelayManager`] so server-side "upstream IP" checks see
    /// the relays the client half has established.
    pub fn set_ip_policy(&mut self, policy: Arc<IpPolicy>) {
        self.ip_policy = Some(policy);
    }

    /// Access the installed IP policy (if any).
    pub fn ip_policy(&self) -> Option<&Arc<IpPolicy>> {
        self.ip_policy.as_ref()
    }

    /// Create a new dual-stack MASQUE relay server
    ///
    /// A dual-stack server can bridge traffic between IPv4 and IPv6 networks,
    /// enabling full connectivity regardless of client/target IP versions.
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration
    /// * `ipv4_address` - IPv4 public address
    /// * `ipv6_address` - IPv6 public address
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let server = MasqueRelayServer::new_dual_stack(
    ///     config,
    ///     "203.0.113.50:9000".parse()?,
    ///     "[2001:db8::1]:9000".parse()?,
    /// );
    /// assert!(server.supports_dual_stack());
    /// ```
    pub fn new_dual_stack(
        config: MasqueRelayConfig,
        ipv4_address: SocketAddr,
        ipv6_address: SocketAddr,
    ) -> Self {
        // Primary is IPv4, secondary is IPv6 (by convention)
        let (primary, secondary) = if ipv4_address.is_ipv4() {
            (ipv4_address, ipv6_address)
        } else {
            (ipv6_address, ipv4_address)
        };

        Self {
            config,
            public_address: ParkingRwLock::new(primary),
            secondary_address: Some(secondary),
            relay_serving_enabled: AtomicBool::new(true),
            sessions: RwLock::new(HashMap::new()),
            client_to_session: RwLock::new(HashMap::new()),
            next_session_id: AtomicU64::new(1),
            stats: Arc::new(MasqueRelayStats::new()),
            started_at: Instant::now(),
            bridged_connections: AtomicU64::new(0),
            reservation_hits: AtomicU64::new(0),
            reservation_misses: AtomicU64::new(0),
            reservations_created: AtomicU64::new(0),
            reservations_expired: AtomicU64::new(0),
            reservations_evicted: AtomicU64::new(0),
            last_reservation_summary_ms: AtomicU64::new(0),
            upnp_mappings: RwLock::new(HashMap::new()),
            reservations: RwLock::new(HashMap::new()),
            forwarding: RwLock::new(HashMap::new()),
            peer_locks: (0..RELAY_PEER_LOCK_STRIPES)
                .map(|_| Mutex::new(()))
                .collect(),
            ip_policy: None,
        }
    }

    /// Enable or disable relay serving.
    ///
    /// Called by the ADR-014 reachability classifier: public nodes leave this
    /// enabled (the default), private nodes disable it so they reject incoming
    /// relay reservation requests.
    pub fn set_relay_serving_enabled(&self, enabled: bool) {
        self.relay_serving_enabled.store(enabled, Ordering::Release);
        if enabled {
            tracing::info!("Relay serving enabled — accepting relay reservation requests");
        } else {
            tracing::info!("Relay serving disabled — rejecting relay reservation requests");
        }
    }

    /// Whether this node is willing to serve as a relay.
    pub fn is_relay_serving_enabled(&self) -> bool {
        self.relay_serving_enabled.load(Ordering::Acquire)
    }

    /// Check if this server supports dual-stack (IPv4 and IPv6)
    pub fn supports_dual_stack(&self) -> bool {
        if let Some(secondary) = self.secondary_address {
            let primary = *self.public_address.read();
            primary.is_ipv4() != secondary.is_ipv4()
        } else {
            false
        }
    }

    /// Check if this server can bridge between the given source and target IP versions
    ///
    /// Returns `true` if:
    /// - Both addresses are the same IP version (no bridging needed)
    /// - The server supports dual-stack (can bridge between versions)
    pub async fn can_bridge(&self, source: SocketAddr, target: SocketAddr) -> bool {
        let source_v4 = source.is_ipv4();
        let target_v4 = target.is_ipv4();

        // Same IP version - always possible
        if source_v4 == target_v4 {
            return true;
        }

        // Different versions - need dual-stack
        self.supports_dual_stack()
    }

    /// Get the appropriate public address for a target IP version
    ///
    /// Returns the IPv4 address for IPv4 targets, IPv6 for IPv6 targets.
    pub fn address_for_target(&self, target: &SocketAddr) -> SocketAddr {
        let primary = *self.public_address.read();
        if let Some(secondary) = self.secondary_address {
            let target_v4 = target.is_ipv4();
            if primary.is_ipv4() == target_v4 {
                primary
            } else {
                secondary
            }
        } else {
            primary
        }
    }

    /// Get secondary address if dual-stack
    pub fn secondary_address(&self) -> Option<SocketAddr> {
        self.secondary_address
    }

    /// Get count of bridged (cross-IP-version) connections
    pub fn bridged_connection_count(&self) -> u64 {
        self.bridged_connections.load(Ordering::Relaxed)
    }

    /// Record a bridged connection
    fn record_bridged_connection(&self) {
        self.bridged_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Get server statistics
    pub fn stats(&self) -> Arc<MasqueRelayStats> {
        Arc::clone(&self.stats)
    }

    /// Get server uptime
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Get public address
    pub fn public_address(&self) -> SocketAddr {
        *self.public_address.read()
    }

    /// Update the public address when the actual external address is discovered.
    ///
    /// The relay server is created with the bind address (e.g., `[::]:10000`),
    /// but after `OBSERVED_ADDRESS` frames arrive, the real external IP is known.
    /// This setter should be called at that point so subsequent relay session
    /// allocations advertise the correct public IP.
    ///
    /// Only the IP is updated — the port is left unchanged because the relay
    /// server's listener port is fixed at bind time.
    ///
    /// Existing sessions keep their original advertised address (the session
    /// response is sent at creation time); only new sessions benefit from the
    /// updated address.
    pub fn set_public_address(&self, addr: SocketAddr) {
        let old = {
            let mut guard = self.public_address.write();
            let old = *guard;
            *guard = addr;
            old
        };
        tracing::info!(
            old = %old,
            new = %addr,
            "Relay server public address updated"
        );
    }

    /// Handle a CONNECT-UDP request (both bind and target modes)
    ///
    /// Creates a new session for the client and returns the response.
    /// If the request specifies a target that requires IP version bridging,
    /// this will only succeed if the server supports dual-stack.
    ///
    /// # Request Modes
    ///
    /// - **Bind mode** (`bind_any()`, `bind_port()`): Client gets a public address
    ///   and can send/receive to any target.
    /// - **Target mode** (`target(addr)`): Client wants to relay traffic to a
    ///   specific destination. Useful for cross-IP-version bridging.
    pub async fn handle_connect_request(
        &self,
        request: &ConnectUdpRequest,
        client_addr: SocketAddr,
        peer_id: Option<RelayPeerId>,
    ) -> RelayResult<ConnectUdpResponse> {
        // ADR-011: opportunistic, rate-limited INFO summary of reservation
        // activity (per-event lines are DEBUG). Driven from the CONNECT path so
        // no background task is needed.
        self.maybe_log_reservation_summary().await;

        // ADR-014: private nodes must not serve as relays because they
        // cannot forward traffic from the public internet. The classifier
        // toggles this flag after determining the node's reachability.
        if !self.is_relay_serving_enabled() {
            return Ok(ConnectUdpResponse::error(
                503,
                "Node is not serving as relay (classified as private)".to_string(),
            ));
        }

        // Enforce the upstream-IP rule: if this node is currently being
        // relayed through an upstream whose IP matches the incoming client's
        // IP, refuse relaying for them. Prevents traffic loops through the
        // same upstream relay. Bypassed on a local testnet (see IpPolicy).
        if let Some(policy) = &self.ip_policy {
            if let Err(denial) = policy.check_accept_client(client_addr) {
                tracing::warn!(
                    client = %client_addr,
                    reason = %denial,
                    "Rejecting relay CONNECT (IP policy: client on upstream relay IP)",
                );
                return Ok(ConnectUdpResponse::error(403, denial.to_string()));
            }
        }

        // ADR-011 [W1]: serialize concurrent CONNECTs from the same authenticated
        // identity via a bounded mutex stripe, so the handover below plus the
        // capacity / duplicate-address checks plus the reclaim-or-bind and session
        // insert form a single critical section per identity. Held to function end.
        let _peer_guard = match peer_id {
            Some(pid) => Some(self.peer_lock(&pid).lock().await),
            None => None,
        };

        // ADR-011 [handover, ordered BEFORE the capacity/duplicate checks]: retire
        // any live session this identity already holds, so an authenticated
        // reconnect is never rejected by the capacity (503) or duplicate-address
        // (409) checks below, and we never leave two live sessions for one
        // identity. close_session cancels and awaits the old session's forwarding
        // loop before leasing its socket, so the old data plane is fully stopped
        // and the reclaim below hands this reconnect back the same port.
        if let Some(pid) = peer_id {
            let old = {
                let sessions = self.sessions.read().await;
                sessions
                    .iter()
                    .find(|(_, s)| s.peer_id() == Some(pid))
                    .map(|(id, _)| *id)
            };
            if let Some(old_sid) = old {
                let _ = self.close_session(old_sid).await;
            }
        }

        // Check session limit
        let current_sessions = self.stats.current_active_sessions();
        if current_sessions >= self.config.max_sessions as u64 {
            return Ok(ConnectUdpResponse::error(
                503,
                "Server at capacity".to_string(),
            ));
        }

        // Check for existing session from this client
        {
            let client_sessions = self.client_to_session.read().await;
            if client_sessions.contains_key(&client_addr) {
                return Ok(ConnectUdpResponse::error(
                    409,
                    "Session already exists for this client".to_string(),
                ));
            }
        }

        // Check if bridging is required and possible
        let requires_bridging = if let Some(target) = request.target_address() {
            let client_v4 = client_addr.is_ipv4();
            let target_v4 = target.is_ipv4();
            client_v4 != target_v4
        } else {
            false
        };

        if requires_bridging && !self.supports_dual_stack() {
            return Ok(ConnectUdpResponse::error(
                501,
                "IPv4/IPv6 bridging not supported by this relay".to_string(),
            ));
        }

        // Determine the public IP to advertise based on client IP version.
        // Snapshot the public_address once under the lock for consistency.
        let primary = *self.public_address.read();
        let public_ip = if client_addr.is_ipv4() {
            if primary.is_ipv4() {
                primary.ip()
            } else {
                self.secondary_address.unwrap_or(primary).ip()
            }
        } else if primary.is_ipv6() {
            primary.ip()
        } else {
            self.secondary_address.unwrap_or(primary).ip()
        };

        // Safety net: if the public IP is still the wildcard bind address
        // (0.0.0.0 or [::]), the OBSERVED_ADDRESS discovery hasn't completed
        // yet and we cannot advertise a routable address. Reject so the
        // client walks to the next candidate rather than publishing 0.0.0.0
        // in the DHT.
        if public_ip.is_unspecified() {
            return Ok(ConnectUdpResponse::error(
                503,
                "Relay server external address not yet discovered".to_string(),
            ));
        }

        // ADR-011: try to hand a reconnecting authenticated peer back its
        // previously retained stable port before binding a fresh random one.
        let reclaimed = match peer_id {
            Some(pid) => self.reclaim_reservation(pid, client_addr.is_ipv4()).await,
            None => None,
        };

        // Bind a real UDP socket for this session's data plane (unless reclaimed).
        // Bind to INADDR_ANY / IN6ADDR_ANY with OS-assigned port, then advertise
        // our public IP with the bound port.
        let (udp_socket, bound_port, reused_upnp) = match reclaimed {
            Some((socket, port, upnp)) => {
                self.reservation_hits.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    component = "relay_reservation",
                    event = "reclaim_hit",
                    peer = %peer_id.map(|p| full_peer_hex(&p)).unwrap_or_default(),
                    port = port,
                    client = %client_addr,
                    "reusing stable relay port for reconnecting peer"
                );
                (socket, port, upnp)
            }
            None => {
                let bind_addr: SocketAddr = if client_addr.is_ipv4() {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                } else {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                };

                let udp_socket =
                    UdpSocket::bind(bind_addr)
                        .await
                        .map_err(|e| RelayError::SessionError {
                            session_id: None,
                            kind: SessionErrorKind::InvalidState {
                                current_state: format!("UDP bind failed: {}", e),
                                expected_state: "bound".into(),
                            },
                        })?;

                // Force DF=1 on the bound socket so oversized egress send_to
                // fails with EMSGSIZE rather than getting silently fragmented.
                // The error then drives a PmtuUpdate control frame back to the
                // relay-client (see [`run_stream_forwarding_loop`]).  If the
                // setsockopt itself fails (very old kernel, exotic platform),
                // we log and proceed: PMTU control frames will simply never
                // fire and the relay falls back to the legacy lossy behaviour.
                if let Err(e) = set_dont_fragment(&udp_socket) {
                    tracing::warn!(
                        error = %e,
                        "Failed to enable IP_DONTFRAG on relay-allocated socket — \
                         oversized egress will silently fragment instead of \
                         surfacing PMTU feedback"
                    );
                }

                let bound_port = udp_socket
                    .local_addr()
                    .map_err(|e| RelayError::SessionError {
                        session_id: None,
                        kind: SessionErrorKind::InvalidState {
                            current_state: format!("Failed to get bound address: {}", e),
                            expected_state: "address available".into(),
                        },
                    })?
                    .port();

                if peer_id.is_some() {
                    self.reservation_misses.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        component = "relay_reservation",
                        event = "reclaim_miss",
                        peer = %peer_id.map(|p| full_peer_hex(&p)).unwrap_or_default(),
                        port = bound_port,
                        client = %client_addr,
                        "no reusable reservation; bound a fresh relay port"
                    );
                }

                (Arc::new(udp_socket), bound_port, None)
            }
        };

        let advertised_address = SocketAddr::new(public_ip, bound_port);

        // Create new session with the bound socket
        let session_id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
        let mut session = RelaySession::new(
            session_id,
            self.config.session_config.clone(),
            advertised_address,
        );
        session.set_client_address(client_addr);
        session.set_peer_id(peer_id);
        session.set_udp_socket(udp_socket);
        if requires_bridging {
            session.set_bridging(true);
        }
        session.activate()?;

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id, session);
        }
        {
            let mut client_map = self.client_to_session.write().await;
            client_map.insert(client_addr, session_id);
        }

        self.stats.record_session_created();
        if requires_bridging {
            self.record_bridged_connection();
        }

        // Best-effort UPnP: reuse the reservation's existing mapping on a
        // reclaim, otherwise ask the local gateway (if any) to forward the
        // freshly-bound relay port. The service tolerates missing gateways.
        let upnp_svc = reused_upnp
            .unwrap_or_else(|| UpnpMappingService::start(bound_port, UpnpConfig::default()));
        self.upnp_mappings
            .write()
            .await
            .insert(session_id, upnp_svc);

        tracing::info!(
            session_id = session_id,
            client = %client_addr,
            public_addr = %advertised_address,
            bound_port = bound_port,
            bridging = requires_bridging,
            dual_stack = self.supports_dual_stack(),
            "MASQUE relay session created with bound UDP socket"
        );

        // Expose the exact session id so the connection handler forwards *this*
        // session rather than re-looking-up by client address (which races with a
        // same-address reconnect). Not part of the wire format.
        let mut response = ConnectUdpResponse::success(Some(advertised_address));
        response.session_id = Some(session_id);
        Ok(response)
    }

    /// Get session for a specific client address
    pub async fn get_session_for_client(&self, client_addr: SocketAddr) -> Option<SessionInfo> {
        let session_id = {
            let client_map = self.client_to_session.read().await;
            client_map.get(&client_addr).copied()?
        };
        self.get_session_info(session_id).await
    }

    /// Terminate session by client address
    pub async fn terminate_session_for_client(&self, client_addr: SocketAddr) {
        let _ = self.close_session_by_client(client_addr).await;
    }

    /// Forward a datagram (used for testing)
    pub async fn forward_datagram(
        &self,
        client_addr: SocketAddr,
        _target: SocketAddr,
        payload: Bytes,
    ) -> RelayResult<()> {
        let session_id = {
            let client_map = self.client_to_session.read().await;
            client_map
                .get(&client_addr)
                .copied()
                .ok_or(RelayError::SessionError {
                    session_id: None,
                    kind: SessionErrorKind::NotFound,
                })?
        };

        let sessions = self.sessions.read().await;
        let session = sessions.get(&session_id).ok_or(RelayError::SessionError {
            session_id: Some(session_id as u32),
            kind: SessionErrorKind::NotFound,
        })?;

        // Check rate limit
        if !session.check_rate_limit(payload.len()) {
            self.stats.record_rate_limit();
            return Err(RelayError::RateLimitExceeded {
                retry_after_ms: 1000, // Wait 1 second before retrying
            });
        }

        // Record statistics
        self.stats.record_bytes(payload.len() as u64);
        self.stats.record_datagram();

        Ok(())
    }

    /// Handle an incoming capsule from a client
    ///
    /// Returns an optional response capsule to send back.
    pub async fn handle_capsule(
        &self,
        client_addr: SocketAddr,
        capsule: Capsule,
    ) -> RelayResult<Option<Capsule>> {
        let session_id = {
            let client_map = self.client_to_session.read().await;
            client_map
                .get(&client_addr)
                .copied()
                .ok_or(RelayError::SessionError {
                    session_id: None,
                    kind: SessionErrorKind::NotFound,
                })?
        };

        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or(RelayError::SessionError {
                session_id: Some(session_id as u32),
                kind: SessionErrorKind::NotFound,
            })?;

        session.handle_capsule(capsule)
    }

    /// Handle an incoming datagram from a client
    ///
    /// Returns information about where the datagram should be forwarded.
    pub async fn handle_client_datagram(
        &self,
        client_addr: SocketAddr,
        datagram: Datagram,
        payload: Bytes,
    ) -> DatagramResult {
        let session_id = {
            let client_map = self.client_to_session.read().await;
            match client_map.get(&client_addr) {
                Some(&id) => id,
                None => return DatagramResult::SessionNotFound,
            }
        };

        let target = {
            let sessions = self.sessions.read().await;
            let session = match sessions.get(&session_id) {
                Some(s) => s,
                None => return DatagramResult::SessionNotFound,
            };

            match session.resolve_target(&datagram) {
                Some(t) => t,
                None => {
                    return DatagramResult::Error(RelayError::ProtocolError {
                        frame_type: 0x00,
                        reason: "Unknown context ID".into(),
                    });
                }
            }
        };

        // Record statistics
        self.stats.record_bytes(payload.len() as u64);
        self.stats.record_datagram();

        DatagramResult::Forward(OutboundDatagram {
            target,
            payload,
            session_id,
        })
    }

    /// Handle an incoming datagram from a target (to be relayed back to client)
    ///
    /// Returns the client address and encoded datagram.
    ///
    /// Fast path uses a **read** lock on the sessions map — when a
    /// compressed context for `source` already exists (the common
    /// case after the first datagram), no other session's forwarding
    /// is blocked.  Only when a new context must be allocated does
    /// this escalate to a write lock.
    pub async fn handle_target_datagram(
        &self,
        session_id: u64,
        source: SocketAddr,
        payload: Bytes,
    ) -> RelayResult<(SocketAddr, Bytes)> {
        // ── Fast path: context already exists, read-lock only. ─────
        {
            let sessions = self.sessions.read().await;
            let session = sessions.get(&session_id).ok_or(RelayError::SessionError {
                session_id: Some(session_id as u32),
                kind: SessionErrorKind::NotFound,
            })?;

            if let Some(ctx_id) = session.existing_context_for_target(source) {
                let client_addr = session.client_address().ok_or(RelayError::SessionError {
                    session_id: Some(session_id as u32),
                    kind: SessionErrorKind::InvalidState {
                        current_state: "no client address".into(),
                        expected_state: "client address set".into(),
                    },
                })?;

                let encoded = crate::masque::CompressedDatagram::new(ctx_id, payload).encode();
                self.stats.record_bytes(encoded.len() as u64);
                self.stats.record_datagram();
                return Ok((client_addr, encoded));
            }
        }

        // ── Slow path: allocate a new context, write-lock required. ─
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or(RelayError::SessionError {
                session_id: Some(session_id as u32),
                kind: SessionErrorKind::NotFound,
            })?;

        let client_addr = session.client_address().ok_or(RelayError::SessionError {
            session_id: Some(session_id as u32),
            kind: SessionErrorKind::InvalidState {
                current_state: "no client address".into(),
                expected_state: "client address set".into(),
            },
        })?;

        let ctx_id = session.context_for_target(source)?;
        let encoded = crate::masque::CompressedDatagram::new(ctx_id, payload).encode();

        self.stats.record_bytes(encoded.len() as u64);
        self.stats.record_datagram();

        Ok((client_addr, encoded))
    }

    /// Run the bidirectional forwarding loop for a relay session.
    ///
    /// Bridges traffic between the QUIC connection to the client and the session's
    /// bound UDP socket. Runs until the connection closes or an unrecoverable error occurs.
    ///
    /// - **QUIC → UDP**: Client sends HTTP Datagrams via QUIC; the relay decapsulates
    ///   the target address and payload and sends raw UDP from the bound socket.
    /// - **UDP → QUIC**: External peers send raw UDP to the bound socket; the relay
    ///   encapsulates source address + payload as an HTTP Datagram and sends via QUIC.
    pub async fn run_forwarding_loop(
        self: &Arc<Self>,
        session_id: u64,
        connection: QuicConnection,
    ) {
        // Get the UDP socket for this session
        let udp_socket = {
            let sessions = self.sessions.read().await;
            match sessions.get(&session_id) {
                Some(s) => s.udp_socket().cloned(),
                None => {
                    tracing::warn!(session_id, "Cannot start forwarding: session not found");
                    return;
                }
            }
        };

        let socket = match udp_socket {
            Some(s) => s,
            None => {
                tracing::warn!(session_id, "Cannot start forwarding: no UDP socket bound");
                return;
            }
        };

        tracing::info!(
            session_id,
            bound_addr = %socket.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            "Starting relay forwarding loop"
        );

        let server = Arc::clone(self);
        let server2 = Arc::clone(self);
        let socket2 = Arc::clone(&socket);
        let conn2 = connection.clone();

        // Run both directions concurrently; exit when either side finishes.
        tokio::select! {
            // Direction 1: UDP → QUIC (target responses → relay → client)
            _ = async {
                let mut buf = vec![0u8; 65536];
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((len, source)) => {
                            let payload = Bytes::copy_from_slice(&buf[..len]);
                            tracing::trace!(
                                session_id,
                                source = %source,
                                len,
                                "RELAY_TUNNEL[srv]: dgram-loop dir1 recv UDP → forwarding to relay-client"
                            );

                            // Encode as uncompressed datagram (includes source address
                            // so client can decode without context registration)
                            let datagram = UncompressedDatagram::new(
                                VarInt::from_u32(0),
                                source,
                                payload.clone(),
                            );
                            let encoded = datagram.encode();

                            // Record stats
                            server.stats.record_bytes(encoded.len() as u64);
                            server.stats.record_datagram();

                            if let Err(e) = connection.send_datagram(encoded) {
                                let err_str = e.to_string();
                                if err_str.contains("too large") || err_str.contains("TooLarge") {
                                    // Skip oversized datagrams (e.g., jumbo UDP from scanners)
                                    tracing::trace!(
                                        session_id,
                                        len,
                                        "Skipping oversized datagram for relay"
                                    );
                                    continue;
                                } else {
                                    tracing::debug!(
                                        session_id,
                                        error = %e,
                                        "Fatal datagram send error, stopping UDP→QUIC"
                                    );
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                session_id,
                                error = %e,
                                "UDP socket recv error, stopping UDP→QUIC"
                            );
                            break;
                        }
                    }
                }
            } => {},

            // Direction 2: QUIC → UDP (client requests → relay → target)
            //
            // Uses `RelaySession::resolve_raw_datagram` to dispatch
            // compressed vs. uncompressed in a single decode pass,
            // using the session's context table as the source of
            // truth. This avoids the previous try-uncompressed-then-
            // try-compressed fallback (which both doubled decode
            // work and could mis-interpret compressed payloads whose
            // first byte happened to look like an IP-version tag).
            _ = async {
                loop {
                    match conn2.read_datagram().await {
                        Ok(data) => {
                            let resolved = {
                                let sessions = server2.sessions.read().await;
                                sessions
                                    .get(&session_id)
                                    .and_then(|s| s.resolve_raw_datagram(&data))
                            };
                            match resolved {
                                Some((target, payload)) => {
                                    tracing::trace!(
                                        session_id,
                                        target = %target,
                                        len = payload.len(),
                                        "RELAY_TUNNEL[srv]: dgram-loop dir2 recv from relay-client → sendto target"
                                    );
                                    server2.stats.record_bytes(payload.len() as u64);
                                    server2.stats.record_datagram();
                                    match socket2.send_to(&payload, target).await {
                                        Ok(n) => {
                                            tracing::trace!(
                                                session_id,
                                                target = %target,
                                                len = payload.len(),
                                                sent = n,
                                                "RELAY_TUNNEL[srv]: dgram-loop dir2 sendto OK"
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                session_id,
                                                target = %target,
                                                error = %e,
                                                "Failed to send UDP to target"
                                            );
                                        }
                                    }
                                }
                                None => {
                                    tracing::debug!(
                                        session_id,
                                        len = data.len(),
                                        "Failed to decode/resolve relay datagram, skipping"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                session_id,
                                error = %e,
                                "QUIC connection closed, stopping QUIC→UDP"
                            );
                            break;
                        }
                    }
                }
            } => {},
        }

        tracing::info!(session_id, "Relay forwarding loop ended");

        // Clean up the session
        if let Err(e) = self.close_session(session_id).await {
            tracing::debug!(session_id, error = %e, "Error closing session after forwarding ended");
        }
    }

    /// Stream-based forwarding loop — uses a persistent bidi QUIC stream instead
    /// of unreliable QUIC datagrams. This avoids the MTU limitation that causes
    /// "datagram too large" errors for QUIC Initial packets (1200+ bytes).
    ///
    /// Protocol: each forwarded packet is framed as [4-byte BE length][payload].
    pub async fn run_stream_forwarding_loop(
        self: &Arc<Self>,
        session_id: u64,
        mut send_stream: crate::high_level::SendStream,
        mut recv_stream: crate::high_level::RecvStream,
    ) {
        // Claim this session's forwarding slot BEFORE touching the socket. The
        // registration (a) lets a concurrent handover close_session cancel this
        // loop and wait until it has released the socket, and (b) guards against a
        // second loop ever running for the same session id (e.g. a racing
        // duplicate from the connection handler). If one is already registered,
        // do not start another.
        let cancel = CancellationToken::new();
        let done = Arc::new(Notify::new());
        let claimed = match self.forwarding.write().await.entry(session_id) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(ForwardingControl {
                    cancel: cancel.clone(),
                    done: done.clone(),
                });
                true
            }
        };
        if !claimed {
            tracing::debug!(
                session_id,
                "stream forwarding already active for session; not starting a second loop"
            );
            return;
        }

        // From here every exit path must call `finish_forwarding` so a handover
        // close_session waiting on `done` is released.
        let udp_socket = {
            let sessions = self.sessions.read().await;
            match sessions.get(&session_id) {
                Some(s) => s.udp_socket().cloned(),
                None => {
                    tracing::warn!(
                        session_id,
                        "Cannot start stream forwarding: session not found"
                    );
                    self.finish_forwarding(session_id, &done).await;
                    return;
                }
            }
        };

        let socket = match udp_socket {
            Some(s) => s,
            None => {
                tracing::warn!(session_id, "Cannot start stream forwarding: no UDP socket");
                self.finish_forwarding(session_id, &done).await;
                return;
            }
        };

        tracing::info!(
            session_id,
            bound_addr = %socket.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            "Starting stream-based relay forwarding loop"
        );

        let socket2 = Arc::clone(&socket);
        let stats = self.stats();
        let stats2 = self.stats();
        let keepalive_bytes = 0u32.to_be_bytes();

        // Direction 1: UDP → Stream (target → relay → client)
        //
        // Decoupled into a reader task and a writer task connected by a
        // bounded channel.  The reader drains the UDP socket into the
        // channel as fast as the kernel delivers packets.  The writer
        // pulls from the channel and writes to the QUIC stream at
        // whatever rate the stream's flow control allows.  The channel
        // acts as a userspace buffer (~10 MB at capacity) that absorbs
        // full max-message-size bursts that would otherwise overflow the
        // kernel's tiny 208 KB UDP receive buffer.
        //
        // The channel carries a tagged item rather than raw bytes so
        // the same writer can interleave normal data frames (Direction
        // 1's forwarded UDP) with out-of-band control frames emitted
        // by Direction 2 when its egress send_to fails with EMSGSIZE.
        let (fwd_tx, mut fwd_rx) =
            tokio::sync::mpsc::channel::<WriterItem>(RELAY_FORWARD_CHANNEL_CAPACITY);
        let ctrl_tx = fwd_tx.clone();

        // Reader: UDP socket → channel (never blocked by stream writes)
        let mut reader_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, source)) => {
                        let payload = Bytes::copy_from_slice(&buf[..len]);
                        tracing::trace!(
                            session_id, source = %source, len,
                            "RELAY_TUNNEL[srv]: stream-loop dir1 recv UDP → forwarding to relay-client"
                        );
                        let datagram =
                            UncompressedDatagram::new(VarInt::from_u32(0), source, payload);
                        let encoded = datagram.encode();
                        stats.record_bytes(encoded.len() as u64);
                        stats.record_datagram();
                        if fwd_tx.send(WriterItem::Data(encoded)).await.is_err() {
                            return "writer_channel_closed";
                        }
                    }
                    Err(e) => {
                        tracing::debug!(session_id, error = %e, "UDP recv error");
                        return "udp_recv_error";
                    }
                }
            }
        });

        // Writer: channel → QUIC stream (paced by stream flow control)
        let mut writer_handle = tokio::spawn(async move {
            let mut keepalive = tokio::time::interval(RELAY_KEEPALIVE_INTERVAL);
            keepalive.tick().await; // skip immediate first tick

            loop {
                tokio::select! {
                    item = fwd_rx.recv() => {
                        let Some(item) = item else {
                            return "forward_channel_closed";
                        };
                        match item {
                            WriterItem::Data(encoded) => {
                                let mut batch = Vec::with_capacity(
                                    encoded
                                        .len()
                                        .saturating_add(std::mem::size_of::<u32>()),
                                );
                                append_relay_frame(&mut batch, &encoded);

                                let mut frames = 1usize;
                                while frames < RELAY_STREAM_BATCH_MAX_FRAMES
                                    && batch.len() < RELAY_STREAM_BATCH_MAX_BYTES
                                {
                                    match fwd_rx.try_recv() {
                                        Ok(WriterItem::Data(next)) => {
                                            append_relay_frame(&mut batch, &next);
                                            frames += 1;
                                        }
                                        Ok(WriterItem::Control(body)) => {
                                            append_control_frame(&mut batch, &body);
                                            break;
                                        }
                                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                                    }
                                }

                                if let Err(e) = send_stream.write_all(&batch).await {
                                    tracing::debug!(session_id, error = %e, frames, bytes = batch.len(), "Stream batch write error");
                                    return "stream_batch_write_error";
                                }
                            }
                            WriterItem::Control(body) => {
                                let mut frame = Vec::with_capacity(
                                    body.len()
                                        .saturating_add(std::mem::size_of::<u64>()),
                                );
                                append_control_frame(&mut frame, &body);
                                if let Err(e) = send_stream.write_all(&frame).await {
                                    tracing::debug!(session_id, error = %e, "Stream write error (control frame)");
                                    return "stream_control_write_error";
                                }
                            }
                        }
                    }
                    _ = keepalive.tick() => {
                        if let Err(e) = send_stream.write_all(&keepalive_bytes).await {
                            tracing::debug!(session_id, error = %e, "Keepalive write error");
                            return "keepalive_write_error";
                        }
                    }
                }
            }
        });

        // Borrow the task handles (`&mut`) so the select! does not consume them;
        // we retain ownership and explicitly abort + await both afterwards so no
        // detached task can keep using the socket (Blocker 1).
        let close_reason = tokio::select! {
            // A handover (or any external close_session) cancels the loop so it
            // stops relaying before its socket is reused.
            _ = cancel.cancelled() => "handover_cancelled",
            result = &mut reader_handle => {
                match result {
                    Ok(reason) => reason,
                    Err(e) => {
                        tracing::debug!(session_id, error = %e, "Relay UDP reader task join error");
                        "reader_task_join_error"
                    }
                }
            },
            result = &mut writer_handle => {
                match result {
                    Ok(reason) => reason,
                    Err(e) => {
                        tracing::debug!(session_id, error = %e, "Relay stream writer task join error");
                        "writer_task_join_error"
                    }
                }
            },

            // Direction 2: Stream → UDP (client → relay → target)
            reason = async {
                loop {
                    // Read 4-byte length prefix
                    let mut len_buf = [0u8; 4];
                    if let Err(e) = recv_stream.read_exact(&mut len_buf).await {
                        tracing::debug!(session_id, error = %e, "Stream read error (length)");
                        return "stream_read_length_error";
                    }
                    let frame_len = u32::from_be_bytes(len_buf) as usize;

                    // Zero-length frame = keepalive ping, skip.
                    if frame_len == 0 {
                        continue;
                    }

                    // Safety cap: reject obviously corrupt length prefixes that
                    // would allocate huge buffers.  Legitimate QUIC packets are
                    // ≤65535 bytes; anything above 512KB is certainly a framing
                    // error or corruption — close the session.
                    const MAX_RELAY_FRAME: usize = 512 * 1024;
                    if frame_len > MAX_RELAY_FRAME {
                        tracing::warn!(
                            session_id,
                            frame_len,
                            "Corrupt stream frame length, closing session"
                        );
                        return "corrupt_frame_length";
                    }

                    // Read frame data
                    let mut frame_buf = vec![0u8; frame_len];
                    if let Err(e) = recv_stream.read_exact(&mut frame_buf).await {
                        tracing::debug!(session_id, error = %e, "Stream read error (data)");
                        return "stream_read_data_error";
                    }

                    // Decode and forward
                    let mut cursor = Bytes::from(frame_buf);
                    match UncompressedDatagram::decode(&mut cursor) {
                        Ok(datagram) => {
                            tracing::trace!(
                                session_id, target = %datagram.target,
                                len = datagram.payload.len(),
                                "RELAY_TUNNEL[srv]: stream-loop dir2 recv from relay-client → sendto target"
                            );
                            stats2.record_bytes(datagram.payload.len() as u64);
                            stats2.record_datagram();
                            let target = datagram.target;
                            let payload_len = datagram.payload.len();
                            match socket2.send_to(&datagram.payload, target).await {
                                Ok(n) => {
                                    tracing::trace!(
                                        session_id,
                                        target = %target,
                                        len = payload_len,
                                        sent = n,
                                        "RELAY_TUNNEL[srv]: stream-loop dir2 sendto OK"
                                    );
                                }
                                Err(e) if is_message_too_large(&e) => {
                                    // Path-MTU exceeded.  Emit a PmtuUpdate
                                    // control frame back through the tunnel
                                    // so the relay-client's MasqueRelaySocket
                                    // can clamp future sends to this target —
                                    // effectively forcing Quinn's DPLPMTUD
                                    // to lower the connection's MTU estimate.
                                    tracing::debug!(
                                        session_id,
                                        target = %target,
                                        len = payload_len,
                                        suggested_mtu = PMTU_FALLBACK_HINT,
                                        "RELAY_TUNNEL[srv]: stream-loop dir2 EMSGSIZE → emitting PmtuUpdate"
                                    );
                                    let body = TunnelControlFrame::PmtuUpdate {
                                        target,
                                        mtu: PMTU_FALLBACK_HINT,
                                    }
                                    .encode_body();
                                    // Best-effort: if the writer is gone or
                                    // its bounded queue is full, avoid
                                    // stalling the client-to-target path.
                                    if let Err(e) = ctrl_tx.try_send(WriterItem::Control(body)) {
                                        tracing::debug!(
                                            session_id,
                                            target = %target,
                                            error = %e,
                                            "RELAY_TUNNEL[srv]: dropped PmtuUpdate control frame"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        session_id, target = %target, error = %e,
                                        "Failed to send UDP to target"
                                    );
                                }
                            }
                        }
                        Err(_) => {
                            tracing::debug!(session_id, "Failed to decode stream frame");
                        }
                    }
                }
            } => reason,
        };

        tracing::info!(
            session_id,
            close_reason,
            "Stream-based relay forwarding loop ended"
        );

        // Blocker 1: stop the forwarding tasks so neither still holds the UDP
        // socket once it can be leased/reclaimed. The select! polled the handles
        // by &mut, so we still own them; abort + await guarantees both tasks have
        // dropped their socket clones before we close (and possibly lease) it.
        reader_handle.abort();
        writer_handle.abort();
        let _ = reader_handle.await;
        let _ = writer_handle.await;

        // Deregister and release any handover waiter now that the tasks are gone
        // and the socket is exclusively owned again. Done BEFORE close_session so
        // the natural-end close sees no live loop and may lease the socket.
        self.finish_forwarding(session_id, &done).await;

        // Natural end: close the session here (which leases the freed socket). On
        // a handover the cancelling close_session owns the close and the lease, so
        // we must not double-close.
        if !cancel.is_cancelled() {
            if let Err(e) = self.close_session(session_id).await {
                tracing::debug!(session_id, error = %e, "Error closing session");
            }
        }
    }

    /// Deregister a session's forwarding control and release any `close_session`
    /// waiting (via `done`) for the loop to fully exit. `notify_one` stores a
    /// permit if no waiter is registered yet, so the signal can't be lost.
    async fn finish_forwarding(&self, session_id: u64, done: &Arc<Notify>) {
        self.forwarding.write().await.remove(&session_id);
        done.notify_one();
    }

    /// Close a specific session.
    ///
    /// When stable ports (ADR-011) are enabled and the session's relayed peer
    /// was authenticated, the bound UDP socket and its UPnP mapping are retained
    /// as a leased reservation — so the same peer can reclaim the port on
    /// reconnect — instead of being dropped.
    pub async fn close_session(&self, session_id: u64) -> RelayResult<()> {
        // Remove the session up-front so we can inspect its identity and socket
        // for a possible stable-port lease before it is dropped.
        let mut session = {
            let mut sessions = self.sessions.write().await;
            sessions
                .remove(&session_id)
                .ok_or(RelayError::SessionError {
                    session_id: Some(session_id as u32),
                    kind: SessionErrorKind::NotFound,
                })?
        };

        // If a forwarding loop is still live for this session, cancel it and wait
        // until it has aborted its tasks and released the socket — so an old
        // session stops relaying before we remove/lease it (no untracked data
        // plane left behind after a handover), and the socket is exclusively
        // owned before it can be reused. Removing the session above serialized
        // concurrent closes, so only one caller reaches this; on a natural end the
        // loop has already deregistered, making this a no-op.
        let control = { self.forwarding.read().await.get(&session_id).cloned() };
        if let Some(control) = control {
            let exited = control.done.notified();
            control.cancel.cancel();
            exited.await;
        }

        session.close();

        if let Some(addr) = session.client_address() {
            let mut client_map = self.client_to_session.write().await;
            client_map.remove(&addr);
        }

        let upnp = self.upnp_mappings.write().await.remove(&session_id);

        // ADR-011: lease the port for reconnect when the peer's authenticated
        // identity is known; otherwise drop the socket and shut the UPnP mapping
        // down (the original behaviour for unauthenticated sessions). The socket
        // is now exclusively owned — any forwarding loop has been cancelled and
        // awaited above — so leasing it is race-free.
        let lease = match (session.peer_id(), session.udp_socket().cloned()) {
            (Some(peer_id), Some(socket)) => Some((peer_id, socket)),
            _ => None,
        };
        match lease {
            Some((peer_id, socket)) => {
                let port = session.public_address().port();
                let client = session.client_address();
                self.lease_reservation(peer_id, client, port, socket, upnp)
                    .await;
            }
            None => {
                if let Some(svc) = upnp {
                    svc.shutdown().await;
                }
            }
        }

        self.stats.record_session_terminated();
        tracing::info!(session_id = session_id, "MASQUE relay session closed");
        Ok(())
    }

    /// ADR-011: retain a closed session's bound socket as a leased stable-port
    /// reservation keyed by the peer's authenticated fingerprint, so the same
    /// peer can reclaim the port on reconnect. Enforces the `max_reservations`
    /// LRU cap, evicting the least-recently-released reservation when full.
    async fn lease_reservation(
        &self,
        peer_id: RelayPeerId,
        client: Option<SocketAddr>,
        port: u16,
        udp_socket: Arc<UdpSocket>,
        upnp: Option<UpnpMappingService>,
    ) {
        let now = Instant::now();
        let (evicted, previous) = {
            let mut reservations = self.reservations.write().await;
            // Enforce the LRU cap, but only when inserting a genuinely new key
            // (replacing an existing key does not grow the map).
            let evicted = if reservations.len() >= self.config.max_reservations
                && !reservations.contains_key(&peer_id)
            {
                let lru = reservations
                    .iter()
                    .min_by_key(|(_, r)| r.released_at)
                    .map(|(k, _)| *k);
                lru.and_then(|k| reservations.remove(&k).map(|r| (k, r)))
            } else {
                None
            };
            let previous = reservations.insert(
                peer_id,
                Reservation {
                    port,
                    udp_socket,
                    upnp,
                    client,
                    released_at: now,
                },
            );
            (evicted, previous)
        };

        // Free evicted / replaced resources outside the lock (shutdown is async).
        if let Some((evicted_key, old)) = evicted {
            self.reservations_evicted.fetch_add(1, Ordering::Relaxed);
            if let Some(svc) = old.upnp {
                svc.shutdown().await;
            }
            // Kept at INFO: rare, and a signal that `max_reservations` is being
            // hit (the cap may be too low).
            tracing::info!(
                component = "relay_reservation",
                event = "reservation_evicted",
                peer = %full_peer_hex(&evicted_key),
                port = old.port,
                client = %client_field(old.client),
                "evicted least-recently-used relay-port reservation (cap reached)"
            );
        }
        if let Some(old) = previous {
            if let Some(svc) = old.upnp {
                svc.shutdown().await;
            }
        }

        self.reservations_created.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            component = "relay_reservation",
            event = "reservation_created",
            peer = %full_peer_hex(&peer_id),
            port = port,
            client = %client_field(client),
            "retained relay port as a leased reservation"
        );
    }

    /// ADR-011: drop stable-port reservations whose lease has exceeded
    /// `reservation_ttl`, freeing the retained ports. Reservations are also
    /// expired lazily on reclaim and bounded by `max_reservations`; this method
    /// lets a caller (or test) sweep idle reservations proactively. Returns the
    /// number expired.
    pub async fn cleanup_expired_reservations(&self) -> usize {
        let ttl = self.config.reservation_ttl;
        let expired: Vec<(RelayPeerId, Reservation)> = {
            let mut reservations = self.reservations.write().await;
            let stale: Vec<RelayPeerId> = reservations
                .iter()
                .filter(|(_, r)| r.released_at.elapsed() >= ttl)
                .map(|(k, _)| *k)
                .collect();
            stale
                .into_iter()
                .filter_map(|k| reservations.remove(&k).map(|r| (k, r)))
                .collect()
        };

        let count = expired.len();
        for (peer_id, res) in expired {
            self.reservations_expired.fetch_add(1, Ordering::Relaxed);
            if let Some(svc) = res.upnp {
                svc.shutdown().await;
            }
            // res.udp_socket drops here → the OS frees the retained port.
            tracing::debug!(
                component = "relay_reservation",
                event = "reservation_expired",
                peer = %full_peer_hex(&peer_id),
                port = res.port,
                client = %client_field(res.client),
                "released expired relay-port reservation"
            );
        }
        if count > 0 {
            tracing::debug!(count, "Cleaned up expired MASQUE relay-port reservations");
        }
        count
    }

    /// ADR-011: attempt to hand a reconnecting authenticated peer back its
    /// previously retained stable port.
    ///
    /// Retires any still-live session for the same identity first (deterministic
    /// handover: `close_session` leases that session's port into `reservations`,
    /// which the take below then reclaims), then returns a reservation that is
    /// both fresh (within `reservation_ttl`) and bound to the client's IP family.
    /// Returns `None` to fall back to a fresh random bind. This never fails — the
    /// caller always has the random-bind fallback, so a reservation problem can
    /// never wedge relay acquisition.
    async fn reclaim_reservation(
        &self,
        peer_id: RelayPeerId,
        want_ipv4: bool,
    ) -> Option<(Arc<UdpSocket>, u16, Option<UpnpMappingService>)> {
        // Deterministic handover (retiring any live session for this identity) is
        // performed up-front in `handle_connect_request`, under the per-identity
        // lock and before the capacity/duplicate checks — so by here there is at
        // most a leased reservation to take, never a live session to close.

        // Take the reservation if present, fresh, and IP-family-compatible.
        let ttl = self.config.reservation_ttl;
        let mut stale_drop: Option<Reservation> = None;
        let reclaimed = {
            let mut reservations = self.reservations.write().await;
            match reservations.remove(&peer_id) {
                Some(res) => {
                    let fresh = res.released_at.elapsed() < ttl;
                    let family_ok = res
                        .udp_socket
                        .local_addr()
                        .map(|a| a.is_ipv4() == want_ipv4)
                        .unwrap_or(false);
                    if fresh && family_ok {
                        Some(res)
                    } else {
                        stale_drop = Some(res);
                        None
                    }
                }
                None => None,
            }
        };

        // Free a stale / mismatched reservation outside the lock.
        if let Some(res) = stale_drop {
            self.reservations_expired.fetch_add(1, Ordering::Relaxed);
            if let Some(svc) = res.upnp {
                svc.shutdown().await;
            }
            tracing::debug!(
                component = "relay_reservation",
                event = "reservation_expired",
                peer = %full_peer_hex(&peer_id),
                port = res.port,
                client = %client_field(res.client),
                "discarded stale/mismatched relay-port reservation on reclaim"
            );
        }

        reclaimed.map(|res| (res.udp_socket, res.port, res.upnp))
    }

    /// ADR-011: emit a rate-limited INFO summary of reservation activity.
    ///
    /// Per-event reservation lines (`reclaim_hit`/`reclaim_miss`/
    /// `reservation_created`/`reservation_expired`) are logged at DEBUG to keep
    /// production log volume low. This instead emits a single INFO "gauge" line
    /// at most once per [`RELAY_RESERVATION_SUMMARY_INTERVAL_MS`] — enough to
    /// confirm on production that reuse is happening (hits climbing) and to see
    /// the reservation pool size — without a per-session firehose. Driven from
    /// the CONNECT path, so it needs no background task; an idle relay simply
    /// has nothing to report.
    async fn maybe_log_reservation_summary(&self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let last = self.last_reservation_summary_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < RELAY_RESERVATION_SUMMARY_INTERVAL_MS {
            return;
        }
        // Claim the interval so only one concurrent CONNECT emits the summary.
        if self
            .last_reservation_summary_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let active_reservations = self.reservations.read().await.len();
        tracing::info!(
            component = "relay_reservation",
            event = "summary",
            hits = self.reservation_hits.load(Ordering::Relaxed),
            misses = self.reservation_misses.load(Ordering::Relaxed),
            created = self.reservations_created.load(Ordering::Relaxed),
            expired = self.reservations_expired.load(Ordering::Relaxed),
            evicted = self.reservations_evicted.load(Ordering::Relaxed),
            active_reservations = active_reservations,
            "relay-reservation activity summary (cumulative counts)"
        );
    }

    /// The mutex stripe that serializes concurrent CONNECTs for a given
    /// authenticated identity (ADR-011). Same fingerprint → same stripe.
    fn peer_lock(&self, peer_id: &RelayPeerId) -> &Mutex<()> {
        &self.peer_locks[peer_id[0] as usize % RELAY_PEER_LOCK_STRIPES]
    }

    /// Close session by client address
    pub async fn close_session_by_client(&self, client_addr: SocketAddr) -> RelayResult<()> {
        let session_id = {
            let client_map = self.client_to_session.read().await;
            client_map
                .get(&client_addr)
                .copied()
                .ok_or(RelayError::SessionError {
                    session_id: None,
                    kind: SessionErrorKind::NotFound,
                })?
        };

        self.close_session(session_id).await
    }

    /// Cleanup expired sessions
    ///
    /// Should be called periodically to remove timed-out sessions.
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let expired_ids: Vec<u64> = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .filter(|(_, s)| s.is_timed_out())
                .map(|(id, _)| *id)
                .collect()
        };

        let count = expired_ids.len();
        for session_id in expired_ids {
            if let Err(e) = self.close_session(session_id).await {
                tracing::warn!(
                    session_id = session_id,
                    error = %e,
                    "Failed to close expired session"
                );
            }
        }

        if count > 0 {
            tracing::debug!(count = count, "Cleaned up expired MASQUE sessions");
        }

        count
    }

    /// Get session count
    pub async fn session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Get session info by ID
    pub async fn get_session_info(&self, session_id: u64) -> Option<SessionInfo> {
        let sessions = self.sessions.read().await;
        sessions.get(&session_id).map(|s| SessionInfo {
            session_id: s.session_id(),
            state: s.state(),
            public_address: s.public_address(),
            client_address: s.client_address(),
            duration: s.duration(),
            stats: s.stats(),
            is_bridging: s.is_bridging(),
        })
    }

    /// Get all active session IDs
    pub async fn active_session_ids(&self) -> Vec<u64> {
        let sessions = self.sessions.read().await;
        sessions
            .iter()
            .filter(|(_, s)| s.is_active())
            .map(|(id, _)| *id)
            .collect()
    }
}

/// Summary information about a session
#[derive(Debug)]
pub struct SessionInfo {
    /// Session identifier
    pub session_id: u64,
    /// Current state
    pub state: RelaySessionState,
    /// Public address assigned
    pub public_address: SocketAddr,
    /// Client address
    pub client_address: Option<SocketAddr>,
    /// Session duration
    pub duration: Duration,
    /// Session statistics
    pub stats: Arc<crate::masque::RelaySessionStats>,
    /// Whether this session is bridging between IP versions
    pub is_bridging: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), port)
    }

    fn client_addr(id: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, id)), 12345)
    }

    // ── ADR-011: stable relay-port reservation tests ──────────────────────

    fn peer_fp(b: u8) -> RelayPeerId {
        [b; 32]
    }

    /// A reconnecting authenticated peer is handed back the same public port.
    #[tokio::test]
    async fn stable_ports_reclaim_reuses_port_on_reconnect() {
        let server = MasqueRelayServer::new(MasqueRelayConfig::default(), test_addr(9000));
        let peer = peer_fp(7);
        let request = ConnectUdpRequest::bind_any();

        let r1 = server
            .handle_connect_request(&request, client_addr(1), Some(peer))
            .await
            .unwrap();
        assert_eq!(r1.status, 200);
        let port1 = r1.proxy_public_address.unwrap().port();

        // Session drops → the port is leased as a reservation.
        server
            .close_session_by_client(client_addr(1))
            .await
            .unwrap();
        assert_eq!(server.session_count().await, 0);
        assert_eq!(server.reservations.read().await.len(), 1);

        // Same identity reconnects from a different client address.
        let r2 = server
            .handle_connect_request(&request, client_addr(2), Some(peer))
            .await
            .unwrap();
        assert_eq!(r2.status, 200);
        let port2 = r2.proxy_public_address.unwrap().port();

        assert_eq!(
            port1, port2,
            "reconnecting peer should reclaim its stable port"
        );
        // Reservation consumed by the reclaim.
        assert_eq!(server.reservations.read().await.len(), 0);
    }

    /// A different identity does not reclaim another peer's retained port.
    #[tokio::test]
    async fn stable_ports_other_identity_does_not_reclaim() {
        let server = MasqueRelayServer::new(MasqueRelayConfig::default(), test_addr(9000));
        let request = ConnectUdpRequest::bind_any();

        let r1 = server
            .handle_connect_request(&request, client_addr(1), Some(peer_fp(1)))
            .await
            .unwrap();
        let port1 = r1.proxy_public_address.unwrap().port();
        server
            .close_session_by_client(client_addr(1))
            .await
            .unwrap();

        // peer_1's reservation still holds port1's socket, so peer_2 cannot get it.
        let r2 = server
            .handle_connect_request(&request, client_addr(2), Some(peer_fp(2)))
            .await
            .unwrap();
        let port2 = r2.proxy_public_address.unwrap().port();
        assert_ne!(port1, port2, "a different identity must not reuse the port");
    }

    /// Without an authenticated identity, no reservation is created.
    #[tokio::test]
    async fn stable_ports_no_identity_creates_no_reservation() {
        let server = MasqueRelayServer::new(MasqueRelayConfig::default(), test_addr(9000));
        let request = ConnectUdpRequest::bind_any();

        server
            .handle_connect_request(&request, client_addr(1), None)
            .await
            .unwrap();
        server
            .close_session_by_client(client_addr(1))
            .await
            .unwrap();

        assert_eq!(server.reservations.read().await.len(), 0);
    }

    /// Reservations past their TTL are swept and their ports freed.
    #[tokio::test]
    async fn stable_ports_reservation_expires_after_ttl() {
        let config = MasqueRelayConfig {
            reservation_ttl: Duration::from_millis(50),
            ..Default::default()
        };
        let server = MasqueRelayServer::new(config, test_addr(9000));
        let request = ConnectUdpRequest::bind_any();

        server
            .handle_connect_request(&request, client_addr(1), Some(peer_fp(7)))
            .await
            .unwrap();
        server
            .close_session_by_client(client_addr(1))
            .await
            .unwrap();
        assert_eq!(server.reservations.read().await.len(), 1);

        tokio::time::sleep(Duration::from_millis(90)).await;
        let expired = server.cleanup_expired_reservations().await;
        assert_eq!(expired, 1);
        assert_eq!(server.reservations.read().await.len(), 0);
    }

    /// The reservation map is bounded by `max_reservations` via LRU eviction.
    #[tokio::test]
    async fn stable_ports_lru_eviction_bounds_reservations() {
        let config = MasqueRelayConfig {
            max_reservations: 2,
            ..Default::default()
        };
        let server = MasqueRelayServer::new(config, test_addr(9000));
        let request = ConnectUdpRequest::bind_any();

        for i in 1..=3u8 {
            server
                .handle_connect_request(&request, client_addr(i), Some(peer_fp(i)))
                .await
                .unwrap();
            server
                .close_session_by_client(client_addr(i))
                .await
                .unwrap();
            // Distinct release timestamps so LRU order is unambiguous.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let reservations = server.reservations.read().await;
        assert_eq!(reservations.len(), 2, "cap must bound the reservation map");
        assert!(
            !reservations.contains_key(&peer_fp(1)),
            "least-recently-released reservation should be evicted"
        );
        assert!(reservations.contains_key(&peer_fp(2)));
        assert!(reservations.contains_key(&peer_fp(3)));
    }

    /// A duplicate/stale live session for the same identity is retired and its
    /// port handed to the new session (deterministic handover).
    #[tokio::test]
    async fn stable_ports_handover_retires_live_session() {
        let server = MasqueRelayServer::new(MasqueRelayConfig::default(), test_addr(9000));
        let peer = peer_fp(7);
        let request = ConnectUdpRequest::bind_any();

        let r1 = server
            .handle_connect_request(&request, client_addr(1), Some(peer))
            .await
            .unwrap();
        let port1 = r1.proxy_public_address.unwrap().port();
        assert_eq!(server.session_count().await, 1);

        // Same identity reconnects from a new address while the old session is
        // still live — handover retires the old and reuses the port.
        let r2 = server
            .handle_connect_request(&request, client_addr(2), Some(peer))
            .await
            .unwrap();
        let port2 = r2.proxy_public_address.unwrap().port();

        assert_eq!(port1, port2, "handover should reuse the port");
        assert_eq!(server.session_count().await, 1, "old session retired");
        assert!(
            server
                .get_session_for_client(client_addr(2))
                .await
                .is_some()
        );
        assert!(
            server
                .get_session_for_client(client_addr(1))
                .await
                .is_none()
        );
    }

    /// Review blocker 2: an authenticated reconnect must retire the peer's
    /// existing session BEFORE the capacity check, so a full relay
    /// (`max_sessions = 1`) still admits the reconnect rather than returning 503.
    #[tokio::test]
    async fn stable_ports_handover_precedes_capacity_check() {
        let config = MasqueRelayConfig {
            max_sessions: 1,
            ..Default::default()
        };
        let server = MasqueRelayServer::new(config, test_addr(9000));
        let peer = peer_fp(7);
        let request = ConnectUdpRequest::bind_any();

        let r1 = server
            .handle_connect_request(&request, client_addr(1), Some(peer))
            .await
            .unwrap();
        assert_eq!(r1.status, 200);
        let port1 = r1.proxy_public_address.unwrap().port();
        assert_eq!(server.session_count().await, 1);

        // Relay is at capacity. The same identity reconnecting from a new address
        // must hand over (retire the old session first), not be rejected with 503.
        let r2 = server
            .handle_connect_request(&request, client_addr(2), Some(peer))
            .await
            .unwrap();
        assert_eq!(
            r2.status, 200,
            "reconnect at capacity must hand over, not 503"
        );
        assert_eq!(server.session_count().await, 1, "old session retired");
        assert_eq!(
            r2.proxy_public_address.unwrap().port(),
            port1,
            "reconnect reclaims the same port"
        );
        assert!(
            server
                .get_session_for_client(client_addr(2))
                .await
                .is_some()
        );
        assert!(
            server
                .get_session_for_client(client_addr(1))
                .await
                .is_none()
        );
    }

    /// Review (round 2) blocker: `close_session` must actively cancel a still-live
    /// forwarding loop and wait for it to exit before returning — so a same-identity
    /// handover stops the old data plane (no untracked loop survives) and only then
    /// leases the socket for reuse.
    #[tokio::test]
    async fn stable_ports_close_cancels_live_forwarding_loop() {
        let server = Arc::new(MasqueRelayServer::new(
            MasqueRelayConfig::default(),
            test_addr(9000),
        ));
        let peer = peer_fp(7);

        let resp = server
            .handle_connect_request(&ConnectUdpRequest::bind_any(), client_addr(1), Some(peer))
            .await
            .unwrap();
        let sid = resp
            .session_id
            .expect("success response carries the created session id");

        // Register a control and spawn a stand-in forwarding loop that runs until
        // close_session cancels it, then deregisters + signals done — exactly what
        // run_stream_forwarding_loop does on cancellation.
        let cancel = CancellationToken::new();
        let done = Arc::new(Notify::new());
        server.forwarding.write().await.insert(
            sid,
            ForwardingControl {
                cancel: cancel.clone(),
                done: done.clone(),
            },
        );
        let exited = Arc::new(AtomicBool::new(false));
        let task = {
            let server = server.clone();
            let exited = exited.clone();
            tokio::spawn(async move {
                cancel.cancelled().await;
                exited.store(true, Ordering::SeqCst);
                server.finish_forwarding(sid, &done).await;
            })
        };

        // Must cancel the stand-in loop and block until it has fully exited.
        server.close_session(sid).await.unwrap();
        assert!(
            exited.load(Ordering::SeqCst),
            "close_session must cancel and await the live forwarding loop"
        );
        let _ = task.await;

        // The socket was leased only after the loop quiesced, so the port is
        // retained for the peer to reclaim on reconnect.
        assert_eq!(
            server.reservations.read().await.len(),
            1,
            "port leased once the loop stopped"
        );
    }

    #[tokio::test]
    async fn test_server_creation() {
        let config = MasqueRelayConfig::default();
        let public_addr = test_addr(9000);
        let server = MasqueRelayServer::new(config, public_addr);

        assert_eq!(server.public_address(), public_addr);
        assert_eq!(server.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_connect_request_creates_session() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));

        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, client_addr(1), None)
            .await
            .unwrap();

        assert_eq!(response.status, 200);
        assert!(response.proxy_public_address.is_some());
        assert_eq!(server.session_count().await, 1);
    }

    #[tokio::test]
    async fn test_duplicate_client_rejected() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));
        let client = client_addr(1);

        let request = ConnectUdpRequest::bind_any();

        // First request succeeds
        let response1 = server
            .handle_connect_request(&request, client, None)
            .await
            .unwrap();
        assert_eq!(response1.status, 200);

        // Second request from same client fails
        let response2 = server
            .handle_connect_request(&request, client, None)
            .await
            .unwrap();
        assert_eq!(response2.status, 409);
    }

    #[tokio::test]
    async fn ip_policy_rejects_client_on_upstream_relay_ip() {
        let policy = IpPolicy::shared();
        let upstream_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
        policy.register_upstream_relay(SocketAddr::new(upstream_ip, 9000));

        let mut server = MasqueRelayServer::new(MasqueRelayConfig::default(), test_addr(9000));
        server.set_ip_policy(Arc::clone(&policy));

        // Client sharing IP with one of our upstream relays: must be rejected (403).
        let offending_client = SocketAddr::new(upstream_ip, 55555);
        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, offending_client, None)
            .await
            .unwrap();
        assert_eq!(response.status, 403);
        assert_eq!(server.session_count().await, 0);

        // Client on any other IP is still accepted.
        let response = server
            .handle_connect_request(&request, client_addr(1), None)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn ip_policy_local_testnet_bypasses_server_rejection() {
        let policy = IpPolicy::shared();
        let upstream_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        policy.register_upstream_relay(SocketAddr::new(upstream_ip, 9000));
        policy.set_local_testnet(true);

        let mut server = MasqueRelayServer::new(MasqueRelayConfig::default(), test_addr(9000));
        server.set_ip_policy(policy);

        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, SocketAddr::new(upstream_ip, 55555), None)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn test_session_limit() {
        let config = MasqueRelayConfig {
            max_sessions: 2,
            ..Default::default()
        };
        let server = MasqueRelayServer::new(config, test_addr(9000));

        let request = ConnectUdpRequest::bind_any();

        // Create 2 sessions
        for i in 1..=2 {
            let response = server
                .handle_connect_request(&request, client_addr(i), None)
                .await
                .unwrap();
            assert_eq!(response.status, 200);
        }

        // Third session should be rejected
        let response = server
            .handle_connect_request(&request, client_addr(3), None)
            .await
            .unwrap();
        assert_eq!(response.status, 503);
    }

    #[tokio::test]
    async fn test_target_request_accepted() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));

        // Target request (regular CONNECT-UDP) - now supported for bridging
        let request = ConnectUdpRequest::target(test_addr(8080));
        let response = server
            .handle_connect_request(&request, client_addr(1), None)
            .await
            .unwrap();

        // Same-version target request should succeed
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn test_close_session() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));

        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, client_addr(1), None)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(server.session_count().await, 1);

        // Get active session ID
        let session_ids = server.active_session_ids().await;
        assert_eq!(session_ids.len(), 1);

        // Close session
        server.close_session(session_ids[0]).await.unwrap();
        assert_eq!(server.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_close_session_by_client() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));
        let client = client_addr(1);

        let request = ConnectUdpRequest::bind_any();
        server
            .handle_connect_request(&request, client, None)
            .await
            .unwrap();
        assert_eq!(server.session_count().await, 1);

        server.close_session_by_client(client).await.unwrap();
        assert_eq!(server.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_server_stats() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));

        let stats = server.stats();
        assert_eq!(stats.current_active_sessions(), 0);

        let request = ConnectUdpRequest::bind_any();
        server
            .handle_connect_request(&request, client_addr(1), None)
            .await
            .unwrap();

        assert_eq!(stats.current_active_sessions(), 1);
        assert_eq!(stats.sessions_created.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_get_session_info() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));
        let client = client_addr(1);

        let request = ConnectUdpRequest::bind_any();
        server
            .handle_connect_request(&request, client, None)
            .await
            .unwrap();

        let session_ids = server.active_session_ids().await;
        let info = server.get_session_info(session_ids[0]).await.unwrap();

        assert_eq!(info.client_address, Some(client));
        assert_eq!(info.state, RelaySessionState::Active);
    }

    // Dual-stack unit tests

    fn ipv4_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), port)
    }

    fn ipv6_addr(port: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            port,
        )
    }

    fn ipv4_client(id: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, id)), 12345)
    }

    fn ipv6_client(id: u8) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, id.into())),
            12345,
        )
    }

    #[tokio::test]
    async fn test_dual_stack_creation() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new_dual_stack(config, ipv4_addr(9000), ipv6_addr(9000));

        assert!(server.supports_dual_stack());
        assert!(server.secondary_address().is_some());
    }

    #[tokio::test]
    async fn test_single_stack_no_dual_stack() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, ipv4_addr(9000));

        assert!(!server.supports_dual_stack());
        assert!(server.secondary_address().is_none());
    }

    #[tokio::test]
    async fn test_can_bridge_same_version() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, ipv4_addr(9000));

        // Same version - always possible
        assert!(server.can_bridge(ipv4_client(1), ipv4_addr(8080)).await);
    }

    #[tokio::test]
    async fn test_can_bridge_different_version_without_dual_stack() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, ipv4_addr(9000));

        // Different version without dual-stack - not possible
        assert!(!server.can_bridge(ipv4_client(1), ipv6_addr(8080)).await);
    }

    #[tokio::test]
    async fn test_can_bridge_different_version_with_dual_stack() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new_dual_stack(config, ipv4_addr(9000), ipv6_addr(9000));

        // Different version with dual-stack - possible
        assert!(server.can_bridge(ipv4_client(1), ipv6_addr(8080)).await);
        assert!(server.can_bridge(ipv6_client(1), ipv4_addr(8080)).await);
    }

    #[tokio::test]
    async fn test_address_for_target_ipv4() {
        let config = MasqueRelayConfig::default();
        let v4 = ipv4_addr(9000);
        let v6 = ipv6_addr(9000);
        let server = MasqueRelayServer::new_dual_stack(config, v4, v6);

        // Should return IPv4 address for IPv4 target
        let addr = server.address_for_target(&ipv4_addr(8080));
        assert!(addr.is_ipv4());
    }

    #[tokio::test]
    async fn test_address_for_target_ipv6() {
        let config = MasqueRelayConfig::default();
        let v4 = ipv4_addr(9000);
        let v6 = ipv6_addr(9000);
        let server = MasqueRelayServer::new_dual_stack(config, v4, v6);

        // Should return IPv6 address for IPv6 target
        let addr = server.address_for_target(&ipv6_addr(8080));
        assert!(addr.is_ipv6());
    }

    #[tokio::test]
    async fn test_bridging_connect_request_rejected_without_dual_stack() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, ipv4_addr(9000));

        // IPv4 client trying to reach IPv6 target on single-stack server
        let request = ConnectUdpRequest::target(ipv6_addr(8080));
        let response = server
            .handle_connect_request(&request, ipv4_client(1), None)
            .await
            .unwrap();

        // Should be rejected because server cannot bridge IPv4→IPv6
        assert_eq!(response.status, 501);
    }

    #[tokio::test]
    async fn test_ipv4_client_session() {
        let config = MasqueRelayConfig::default();
        let v4 = ipv4_addr(9000);
        let v6 = ipv6_addr(9000);
        let server = MasqueRelayServer::new_dual_stack(config, v4, v6);

        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, ipv4_client(1), None)
            .await
            .unwrap();

        assert_eq!(response.status, 200);
        // IPv4 client should receive IPv4 public address
        let public_addr = response.proxy_public_address.unwrap();
        assert!(public_addr.is_ipv4());
    }

    #[tokio::test]
    async fn test_ipv6_client_session() {
        let config = MasqueRelayConfig::default();
        let v4 = ipv4_addr(9000);
        let v6 = ipv6_addr(9000);
        let server = MasqueRelayServer::new_dual_stack(config, v4, v6);

        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, ipv6_client(1), None)
            .await
            .unwrap();

        assert_eq!(response.status, 200);
        // IPv6 client should receive IPv6 public address
        let public_addr = response.proxy_public_address.unwrap();
        assert!(public_addr.is_ipv6());
    }

    #[tokio::test]
    async fn test_bridged_connection_count() {
        let config = MasqueRelayConfig::default();
        let v4 = ipv4_addr(9000);
        let v6 = ipv6_addr(9000);
        let server = MasqueRelayServer::new_dual_stack(config, v4, v6);

        assert_eq!(server.bridged_connection_count(), 0);

        // Regular same-version session (no bridging)
        let request = ConnectUdpRequest::bind_any();
        server
            .handle_connect_request(&request, ipv4_client(1), None)
            .await
            .unwrap();

        // No bridging for bind_any (no target specified)
        assert_eq!(server.bridged_connection_count(), 0);
    }

    #[tokio::test]
    async fn test_session_bridging_flag() {
        let config = MasqueRelayConfig::default();
        let v4 = ipv4_addr(9000);
        let v6 = ipv6_addr(9000);
        let server = MasqueRelayServer::new_dual_stack(config, v4, v6);

        let request = ConnectUdpRequest::bind_any();
        server
            .handle_connect_request(&request, ipv4_client(1), None)
            .await
            .unwrap();

        let session_ids = server.active_session_ids().await;
        let info = server.get_session_info(session_ids[0]).await.unwrap();

        // bind_any has no target, so no bridging
        assert!(!info.is_bridging);
    }
}
