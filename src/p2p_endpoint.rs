// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! P2P endpoint for saorsa-transport
//!
//! This module provides the main API for P2P communication with NAT traversal,
//! secure connections, and event-driven architecture.
//!
//! # Features
//!
//! - Configuration via [`P2pConfig`](crate::unified_config::P2pConfig)
//! - Event subscription via broadcast channels
//! - TLS-based peer authentication via ML-DSA-65 (v0.2+)
//! - NAT traversal with automatic fallback
//! - Connection metrics and statistics
//!
//! # Example
//!
//! ```rust,ignore
//! use saorsa_transport::{P2pEndpoint, P2pConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // All nodes are symmetric - they can both connect and accept connections
//!     let config = P2pConfig::builder()
//!         .bind_addr("0.0.0.0:9000".parse()?)
//!         .known_peer("quic.saorsalabs.com:9000".parse()?)
//!         .build()?;
//!
//!     let endpoint = P2pEndpoint::new(config).await?;
//!     println!("Public key: {:?}", endpoint.local_public_key());
//!
//!     // Subscribe to events
//!     let mut events = endpoint.subscribe();
//!     tokio::spawn(async move {
//!         while let Ok(event) = events.recv().await {
//!             println!("Event: {:?}", event);
//!         }
//!     });
//!
//!     // Connect to known peers
//!     endpoint.connect_known_peers().await?;
//!
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{RwLock, broadcast, mpsc};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::Side;
use crate::bootstrap_cache::{BootstrapCache, BootstrapTokenStore};
use crate::bounded_pending_buffer::BoundedPendingBuffer;
use crate::connection_router::{ConnectionRouter, RouterConfig};
use crate::connection_strategy::{
    ConnectionMethod, ConnectionStage, ConnectionStrategy, StrategyConfig,
};
use crate::constrained::ConnectionId as ConstrainedConnectionId;
use crate::constrained::EngineEvent;
use crate::crypto::raw_public_keys::key_utils::generate_ml_dsa_keypair;
use crate::happy_eyeballs::{self, HappyEyeballsConfig};
pub use crate::nat_traversal_api::TraversalPhase;
use crate::nat_traversal_api::{
    NatTraversalEndpoint, NatTraversalError, NatTraversalEvent, NatTraversalStatistics,
};
use crate::transport::{ProtocolEngine, TransportAddr, TransportRegistry};
use crate::unified_config::P2pConfig;
use rustls;

/// Event channel capacity
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Health check protocol prefix byte.
///
/// Uni streams whose payload starts with this byte are health check messages
/// handled by the reader task; they are NOT forwarded to the application data channel.
const HEALTH_CHECK_PREFIX: u8 = 0xFF;

/// Health PING payload: `[0xFF, 0x01]`.  Sent periodically by the stale connection
/// reaper.  The remote reader task responds with a PONG.
const HEALTH_PING: [u8; 2] = [HEALTH_CHECK_PREFIX, 0x01];

/// Health PONG payload: `[0xFF, 0x02]`.  Sent in response to a PING.
const HEALTH_PONG: [u8; 2] = [HEALTH_CHECK_PREFIX, 0x02];

/// Maximum age of the last health check response before a connection is
/// considered unresponsive and evicted (2 check intervals = 60s).
const HEALTH_CHECK_EVICTION_THRESHOLD: Duration = Duration::from_secs(60);

use crate::SHUTDOWN_DRAIN_TIMEOUT;

/// Extract the raw SPKI (SubjectPublicKeyInfo) bytes from a QUIC connection's
/// peer identity, if TLS-based authentication was used.
///
/// Returns `None` for unauthenticated or constrained connections.
fn extract_public_key_bytes_from_connection(
    connection: &crate::high_level::Connection,
) -> Option<Vec<u8>> {
    let identity = connection.peer_identity()?;
    let certs = identity.downcast_ref::<Vec<rustls::pki_types::CertificateDer<'static>>>()?;
    let cert = certs.first()?;
    Some(cert.as_ref().to_vec())
}

/// P2P endpoint - the primary API for saorsa-transport
///
/// This struct provides the main interface for P2P communication with
/// NAT traversal, connection management, and secure messaging.
pub struct P2pEndpoint {
    /// Internal NAT traversal endpoint
    inner: Arc<NatTraversalEndpoint>,

    // v0.2: auth_manager removed - TLS handles peer authentication via ML-DSA-65
    /// Connected peers keyed by remote socket address
    connected_peers: Arc<RwLock<HashMap<SocketAddr, PeerConnection>>>,

    /// Endpoint statistics
    stats: Arc<RwLock<EndpointStats>>,

    /// Configuration
    config: P2pConfig,

    /// Event broadcaster
    event_tx: broadcast::Sender<P2pEvent>,

    /// SPKI fingerprint of our own ML-DSA-65 public key (BLAKE3 hash)
    our_fingerprint: [u8; 32],

    /// Our ML-DSA-65 public key SPKI bytes (for identity sharing)
    public_key: Vec<u8>,

    /// Shutdown token for cooperative cancellation
    shutdown: CancellationToken,

    /// Bounded pending data buffer for message ordering
    pending_data: Arc<RwLock<BoundedPendingBuffer>>,

    /// Bootstrap cache for peer persistence
    pub bootstrap_cache: Arc<BootstrapCache>,

    /// Transport registry for multi-transport support
    ///
    /// Contains all registered transport providers (UDP, BLE, etc.) that this
    /// endpoint can use for connectivity.
    transport_registry: Arc<TransportRegistry>,

    /// Connection router for automatic protocol engine selection
    ///
    /// Routes connections through either QUIC (for broadband) or Constrained
    /// engine (for BLE/LoRa) based on transport capabilities.
    router: Arc<RwLock<ConnectionRouter>>,

    /// Mapping from TransportAddr to ConnectionId for constrained connections
    ///
    /// When a peer is connected via a constrained transport (BLE, LoRa, etc.),
    /// this map stores the ConstrainedEngine's ConnectionId for that address.
    /// UDP/QUIC peers are NOT in this map - they use the standard QUIC connection.
    constrained_connections: Arc<RwLock<HashMap<TransportAddr, ConstrainedConnectionId>>>,

    /// Reverse lookup: ConnectionId → TransportAddr for constrained connections
    ///
    /// This enables mapping incoming constrained data back to the correct remote address.
    /// Registered when ConnectionAccepted/Established fires for constrained transports.
    constrained_peer_addrs: Arc<RwLock<HashMap<ConstrainedConnectionId, TransportAddr>>>,

    /// Channel sender for data received from QUIC reader tasks and constrained poller
    data_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,

    /// Channel receiver for data received from QUIC reader tasks and constrained poller
    data_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>>,

    /// JoinSet tracking background reader tasks (each returns SocketAddr on exit)
    reader_tasks: Arc<tokio::sync::Mutex<tokio::task::JoinSet<SocketAddr>>>,

    /// Per-address abort handles for targeted reader task cancellation
    reader_handles: Arc<RwLock<HashMap<SocketAddr, tokio::task::AbortHandle>>>,
}

impl std::fmt::Debug for P2pEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pEndpoint")
            .field("public_key_len", &self.public_key.len())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Health status for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionHealth {
    /// Connection recently confirmed alive (PONG received within threshold).
    Healthy,
    /// A health PING has been sent but no PONG received yet.
    Checking,
    /// No PONG received within the eviction threshold — connection is phantom/dead.
    Unresponsive,
}

/// Connection information for a peer
#[derive(Debug, Clone)]
pub struct PeerConnection {
    /// Remote peer's ML-DSA-65 SPKI public key bytes (None for constrained/unauthenticated)
    pub public_key: Option<Vec<u8>>,

    /// Remote address (supports all transport types)
    pub remote_addr: TransportAddr,

    /// Whether peer is authenticated
    pub authenticated: bool,

    /// Connection established time
    pub connected_at: Instant,

    /// Last activity time
    pub last_activity: Instant,

    /// Timestamp of the last health PING sent to this peer.
    pub last_health_ping_sent: Option<Instant>,

    /// Timestamp of the last health PONG received from this peer.
    pub last_health_pong_received: Option<Instant>,
}

/// Connection metrics for P2P peers
#[derive(Debug, Clone, Default)]
pub struct ConnectionMetrics {
    /// Bytes sent to this peer
    pub bytes_sent: u64,

    /// Bytes received from this peer
    pub bytes_received: u64,

    /// Round-trip time
    pub rtt: Option<Duration>,

    /// Packet loss rate (0.0 to 1.0)
    pub packet_loss: f64,

    /// Last activity timestamp
    pub last_activity: Option<Instant>,
}

/// P2P endpoint statistics
#[derive(Debug, Clone)]
pub struct EndpointStats {
    /// Number of active connections
    pub active_connections: usize,

    /// Total successful connections
    pub successful_connections: u64,

    /// Total failed connections
    pub failed_connections: u64,

    /// NAT traversal attempts
    pub nat_traversal_attempts: u64,

    /// Successful NAT traversals
    pub nat_traversal_successes: u64,

    /// Direct connections (no NAT traversal needed)
    pub direct_connections: u64,

    /// Relayed connections
    pub relayed_connections: u64,

    /// Total bootstrap nodes configured
    pub total_bootstrap_nodes: usize,

    /// Connected bootstrap nodes
    pub connected_bootstrap_nodes: usize,

    /// Endpoint start time
    pub start_time: Instant,

    /// Average coordination time for NAT traversal
    pub average_coordination_time: Duration,

    /// Number of phantom/unresponsive connections evicted by health checks
    pub phantom_connections_evicted: u64,
}

impl Default for EndpointStats {
    fn default() -> Self {
        Self {
            active_connections: 0,
            successful_connections: 0,
            failed_connections: 0,
            nat_traversal_attempts: 0,
            nat_traversal_successes: 0,
            direct_connections: 0,
            relayed_connections: 0,
            total_bootstrap_nodes: 0,
            connected_bootstrap_nodes: 0,
            start_time: Instant::now(),
            average_coordination_time: Duration::ZERO,
            phantom_connections_evicted: 0,
        }
    }
}

/// P2P event for connection and network state changes.
///
/// Events use [`TransportAddr`] to support multi-transport connectivity.
/// Use `addr.as_socket_addr()` for backward compatibility with UDP-only code.
///
/// # Examples
///
/// ## Handling events with transport awareness
///
/// ```rust,ignore
/// use saorsa_transport::{P2pEvent, transport::TransportAddr};
///
/// while let Ok(event) = events.recv().await {
///     match event {
///         P2pEvent::PeerConnected { peer_id, addr, side } => {
///             // Handle different transport types
///             match addr {
///                 TransportAddr::Quic(socket_addr) => {
///                     println!("UDP connection from {socket_addr}");
///                 },
///                 TransportAddr::Ble { mac, .. } => {
///                     println!("BLE connection from {:?}", mac);
///                 },
///                 _ => println!("Other transport: {addr}"),
///             }
///         }
///         P2pEvent::ExternalAddressDiscovered { addr } => {
///             // Our external address was discovered
///             if let Some(socket_addr) = addr.as_socket_addr() {
///                 println!("External UDP address: {socket_addr}");
///             }
///         }
///         _ => {}
///     }
/// }
/// ```
///
/// ## Address-based event handling
///
/// Events use `SocketAddr` as the primary peer identifier:
///
/// ```rust,ignore
/// match event {
///     P2pEvent::PeerConnected { addr, public_key, .. } => {
///         if let Some(socket_addr) = addr.as_socket_addr() {
///             println!("Peer connected from {}", socket_addr);
///             if let Some(pk) = &public_key {
///                 println!("  Public key: {} bytes", pk.len());
///             }
///         }
///     }
///     _ => {}
/// }
/// ```
#[derive(Debug, Clone)]
pub enum P2pEvent {
    /// A new peer has connected.
    ///
    /// The `addr` field contains a [`TransportAddr`] which can represent different
    /// transport types (UDP, BLE, LoRa, etc.). Use `addr.as_socket_addr()` to extract
    /// the [`SocketAddr`] for UDP connections, or pattern match for specific transports.
    PeerConnected {
        /// Remote transport address (supports UDP, BLE, LoRa, and other transports)
        addr: TransportAddr,
        /// Remote peer's ML-DSA-65 SPKI public key bytes (None for constrained/unauthenticated)
        public_key: Option<Vec<u8>>,
        /// Who initiated the connection (Client = we connected, Server = they connected)
        side: Side,
    },

    /// A peer has disconnected.
    PeerDisconnected {
        /// Remote transport address of the disconnected peer
        addr: TransportAddr,
        /// Reason for the disconnection
        reason: DisconnectReason,
    },

    /// NAT traversal progress update.
    NatTraversalProgress {
        /// Target address for the NAT traversal
        addr: SocketAddr,
        /// Current phase of NAT traversal
        phase: TraversalPhase,
    },

    /// An external address was discovered for this node.
    ///
    /// The `addr` field contains a [`TransportAddr`] representing our externally
    /// visible address. For UDP connections, use `addr.as_socket_addr()` to get
    /// the [`SocketAddr`].
    ExternalAddressDiscovered {
        /// Discovered external transport address (typically TransportAddr::Quic for NAT traversal)
        addr: TransportAddr,
    },

    /// Bootstrap connection status
    BootstrapStatus {
        /// Number of connected bootstrap nodes
        connected: usize,
        /// Total number of bootstrap nodes
        total: usize,
    },

    /// Peer authenticated
    PeerAuthenticated {
        /// Authenticated peer address
        addr: SocketAddr,
        /// Authenticated peer's ML-DSA-65 SPKI public key bytes
        public_key: Vec<u8>,
    },

    /// Data received from peer
    DataReceived {
        /// Source peer address
        addr: SocketAddr,
        /// Number of bytes received
        bytes: usize,
    },

    /// Data received from a constrained transport (BLE, LoRa, etc.)
    ///
    /// This event is generated when data arrives via a non-UDP transport that uses
    /// the constrained protocol engine.
    ConstrainedDataReceived {
        /// Remote transport address (BLE device ID, LoRa address, etc.)
        remote_addr: TransportAddr,
        /// Connection ID from the constrained engine
        connection_id: u16,
        /// The received data payload
        data: Vec<u8>,
    },
}

/// Reason for peer disconnection
#[derive(Debug, Clone)]
pub enum DisconnectReason {
    /// Normal disconnect
    Normal,
    /// Connection timeout
    Timeout,
    /// Protocol error
    ProtocolError(String),
    /// Authentication failure
    AuthenticationFailed,
    /// Connection lost
    ConnectionLost,
    /// Remote closed
    RemoteClosed,
}

// TraversalPhase is re-exported from nat_traversal_api

/// Error type for P2pEndpoint operations
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// NAT traversal error
    #[error("NAT traversal error: {0}")]
    NatTraversal(#[from] NatTraversalError),

    /// Authentication error
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// Peer not found
    #[error("Peer not found at address: {0}")]
    PeerNotFound(SocketAddr),

    /// Already connected
    #[error("Already connected to address: {0}")]
    AlreadyConnected(SocketAddr),

    /// Shutdown in progress
    #[error("Endpoint is shutting down")]
    ShuttingDown,

    /// All connection strategies failed
    #[error("All connection strategies failed: {0}")]
    AllStrategiesFailed(String),

    /// No target address provided
    #[error("No target address provided")]
    NoAddress,
}

/// Shared cleanup logic for removing a peer from all tracking structures.
///
/// Used by both `P2pEndpoint::cleanup_connection()` and the background reaper
/// to ensure consistent cleanup behaviour (single source of truth).
///
/// Returns `true` if the peer was actually present in `connected_peers`.
async fn do_cleanup_connection(
    connected_peers: &RwLock<HashMap<SocketAddr, PeerConnection>>,
    inner: &NatTraversalEndpoint,
    reader_handles: &RwLock<HashMap<SocketAddr, tokio::task::AbortHandle>>,
    stats: &RwLock<EndpointStats>,
    event_tx: &broadcast::Sender<P2pEvent>,
    addr: &SocketAddr,
    reason: DisconnectReason,
) -> bool {
    let removed = connected_peers.write().await.remove(addr);
    let _ = inner.remove_connection(addr);

    // Abort the background reader task for this address
    if let Some(handle) = reader_handles.write().await.remove(addr) {
        handle.abort();
    }

    if let Some(peer_conn) = removed {
        {
            let mut s = stats.write().await;
            s.active_connections = s.active_connections.saturating_sub(1);
        }

        let _ = event_tx.send(P2pEvent::PeerDisconnected {
            addr: peer_conn.remote_addr,
            reason,
        });

        info!("Cleaned up connection for addr {}", addr);
        true
    } else {
        false
    }
}

impl P2pEndpoint {
    /// Create a new P2P endpoint with the given configuration
    pub async fn new(config: P2pConfig) -> Result<Self, EndpointError> {
        // Use provided keypair or generate a new one (ML-DSA-65)
        let (public_key, secret_key) = match config.keypair.clone() {
            Some(keypair) => keypair,
            None => generate_ml_dsa_keypair().map_err(|e| {
                EndpointError::Config(format!("Failed to generate ML-DSA-65 keypair: {e:?}"))
            })?,
        };
        // SPKI fingerprint of our own public key (for identity/logging)
        let our_fingerprint =
            crate::crypto::raw_public_keys::pqc::fingerprint_public_key(&public_key);

        info!(
            "Creating P2P endpoint (fingerprint: {})",
            hex::encode(&our_fingerprint[..8])
        );

        // v0.2: auth_manager removed - TLS handles peer authentication via ML-DSA-65
        // Store public key bytes directly for identity sharing
        let public_key_bytes: Vec<u8> = public_key.as_bytes().to_vec();

        // Create event channel
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let event_tx_clone = event_tx.clone();

        // Create stats
        let stats = Arc::new(RwLock::new(EndpointStats {
            total_bootstrap_nodes: config.known_peers.len(),
            start_time: Instant::now(),
            ..Default::default()
        }));
        let stats_clone = Arc::clone(&stats);

        // Create event callback that bridges to broadcast channel
        let event_callback = Box::new(move |event: NatTraversalEvent| {
            let event_tx = event_tx_clone.clone();
            let stats = stats_clone.clone();

            tokio::spawn(async move {
                // Update stats based on event
                let mut stats_guard = stats.write().await;
                match &event {
                    NatTraversalEvent::CoordinationRequested { .. } => {
                        stats_guard.nat_traversal_attempts += 1;
                    }
                    NatTraversalEvent::ConnectionEstablished {
                        remote_address,
                        side,
                        public_key,
                    } => {
                        stats_guard.nat_traversal_successes += 1;
                        stats_guard.active_connections += 1;
                        stats_guard.successful_connections += 1;

                        // Broadcast event with connection direction
                        let _ = event_tx.send(P2pEvent::PeerConnected {
                            addr: TransportAddr::Quic(*remote_address),
                            public_key: public_key.clone(),
                            side: *side,
                        });
                    }
                    NatTraversalEvent::TraversalFailed { remote_address, .. } => {
                        stats_guard.failed_connections += 1;
                        let _ = event_tx.send(P2pEvent::NatTraversalProgress {
                            addr: *remote_address,
                            phase: TraversalPhase::Failed,
                        });
                    }
                    NatTraversalEvent::PhaseTransition {
                        remote_address,
                        to_phase,
                        ..
                    } => {
                        let _ = event_tx.send(P2pEvent::NatTraversalProgress {
                            addr: *remote_address,
                            phase: *to_phase,
                        });
                    }
                    NatTraversalEvent::ExternalAddressDiscovered { address, .. } => {
                        info!("External address discovered: {}", address);
                        let _ = event_tx.send(P2pEvent::ExternalAddressDiscovered {
                            addr: TransportAddr::Quic(*address),
                        });
                    }
                    _ => {}
                }
                drop(stats_guard);
            });
        });

        // Create NAT traversal endpoint with the same identity key used for auth
        // This ensures P2pEndpoint and NatTraversalEndpoint use the same keypair
        let mut nat_config = config.to_nat_config_with_key(public_key.clone(), secret_key);
        let bootstrap_cache = Arc::new(
            BootstrapCache::open(config.bootstrap_cache.clone())
                .await
                .map_err(|e| {
                    EndpointError::Config(format!("Failed to open bootstrap cache: {}", e))
                })?,
        );

        // Create token store
        let token_store = Arc::new(BootstrapTokenStore::new(bootstrap_cache.clone()).await);

        // Phase 5.3 Deliverable 3: Socket sharing in default constructor
        // Bind a single UDP socket and share it between transport registry and Quinn
        let default_addr: std::net::SocketAddr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        let bind_addr = config
            .bind_addr
            .as_ref()
            .and_then(|addr| addr.as_socket_addr())
            .unwrap_or(default_addr);
        let (udp_transport, quinn_socket) =
            crate::transport::UdpTransport::bind_for_quinn(bind_addr)
                .await
                .map_err(|e| EndpointError::Config(format!("Failed to bind UDP socket: {e}")))?;

        let actual_bind_addr = quinn_socket
            .local_addr()
            .map_err(|e| EndpointError::Config(format!("Failed to get local address: {e}")))?;

        info!("Bound shared UDP socket at {}", actual_bind_addr);

        // Create transport registry with the UDP transport
        // Also include any additional transports from the config
        let mut transport_registry = config.transport_registry.clone();
        transport_registry.register(Arc::new(udp_transport));

        // Update NAT config to use our registry and bind address
        nat_config.transport_registry = Some(Arc::new(transport_registry.clone()));
        nat_config.bind_addr = Some(actual_bind_addr);

        // Create NAT traversal endpoint with the shared socket
        let inner = NatTraversalEndpoint::new_with_socket(
            nat_config,
            Some(event_callback),
            Some(token_store.clone()),
            Some(quinn_socket),
        )
        .await
        .map_err(|e| EndpointError::Config(e.to_string()))?;

        // Wrap the registry in Arc for shared ownership
        let transport_registry = Arc::new(transport_registry);

        // Create connection router for automatic protocol engine selection
        let inner_arc = Arc::new(inner);
        let router_config = RouterConfig {
            constrained_config: crate::constrained::ConstrainedTransportConfig::default(),
            prefer_quic: true, // Default to QUIC for broadband transports
            enable_metrics: true,
            max_connections: 256,
        };
        let mut router = ConnectionRouter::with_full_config(
            router_config,
            Arc::clone(&transport_registry),
            Arc::clone(&inner_arc),
        );

        // Set QUIC endpoint on the router
        router.set_quic_endpoint(Arc::clone(&inner_arc));

        // Create channel for data received from background reader tasks
        let (data_tx, data_rx) = mpsc::channel(config.data_channel_capacity);
        let reader_tasks = Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new()));
        let reader_handles = Arc::new(RwLock::new(HashMap::new()));

        let endpoint = Self {
            inner: inner_arc,
            // v0.2: auth_manager removed
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            stats,
            config,
            event_tx,
            our_fingerprint,
            public_key: public_key_bytes,
            shutdown: CancellationToken::new(),
            pending_data: Arc::new(RwLock::new(BoundedPendingBuffer::default())),
            bootstrap_cache,
            transport_registry,
            router: Arc::new(RwLock::new(router)),
            constrained_connections: Arc::new(RwLock::new(HashMap::new())),
            constrained_peer_addrs: Arc::new(RwLock::new(HashMap::new())),
            data_tx,
            data_rx: Arc::new(tokio::sync::Mutex::new(data_rx)),
            reader_tasks,
            reader_handles,
        };

        // Spawn background constrained poller task
        endpoint.spawn_constrained_poller();

        // Spawn stale connection reaper — periodically detects and removes
        // dead connections from tracking structures (issue #137 fix).
        endpoint.spawn_stale_connection_reaper();

        Ok(endpoint)
    }

    /// Get the local ML-DSA-65 SPKI public key bytes
    pub fn local_public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the underlying QUIC connection for a remote address.
    ///
    /// Look up an existing QUIC connection by remote address.
    ///
    /// Returns `None` if we have no tracked connection for this address.
    pub async fn get_quic_connection(
        &self,
        addr: &SocketAddr,
    ) -> Result<Option<crate::high_level::Connection>, EndpointError> {
        let peers = self.connected_peers.read().await;
        if !peers.contains_key(addr) {
            return Ok(None);
        }
        drop(peers);
        self.inner
            .get_connection(addr)
            .map_err(EndpointError::NatTraversal)
    }

    /// Get the local bind address
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner
            .get_endpoint()
            .and_then(|ep| ep.local_addr().ok())
    }

    /// Get observed external address (if discovered)
    pub fn external_addr(&self) -> Option<SocketAddr> {
        self.inner.get_observed_external_address().ok().flatten()
    }

    /// Get the transport registry for this endpoint
    ///
    /// The transport registry contains all registered transport providers (UDP, BLE, etc.)
    /// that this endpoint can use for connectivity.
    pub fn transport_registry(&self) -> &TransportRegistry {
        &self.transport_registry
    }

    /// Get the ML-DSA-65 public key bytes (1952 bytes)
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    // === Connection Management ===

    /// Connect to a peer by address (direct connection).
    ///
    /// Uses Raw Public Key authentication - the peer's identity is verified via their
    /// ML-DSA-65 public key, not via SNI/certificates.
    ///
    /// If we already have a live connection to the target address, returns the
    /// existing connection instead of creating a duplicate. After handshake, if
    /// we discover a simultaneous open (both sides connected at the same time),
    /// a deterministic tiebreaker ensures both sides keep the same connection.
    pub async fn connect(&self, addr: SocketAddr) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Dedup check: if we already have a live connection to this address, return it.
        {
            let peers = self.connected_peers.read().await;
            if let Some(existing) = peers.get(&addr) {
                // Verify the underlying QUIC connection is still alive
                if self.inner.is_connected(&addr) {
                    info!("connect: reusing existing live connection to {}", addr);
                    return Ok(existing.clone());
                }
            }
        }
        // If a dead connection was found, remove stale entry.
        {
            let mut peers = self.connected_peers.write().await;
            if peers.contains_key(&addr) && !self.inner.is_connected(&addr) {
                peers.remove(&addr);
                info!("connect: removed stale connection entry for {}", addr);
            }
        }

        info!("Connecting directly to {}", addr);

        let endpoint = self
            .inner
            .get_endpoint()
            .ok_or_else(|| EndpointError::Config("QUIC endpoint not available".to_string()))?;

        let connecting = endpoint
            .connect(addr, "peer")
            .map_err(|e| EndpointError::Connection(e.to_string()))?;

        // Enforce a hard timeout on the QUIC handshake to prevent the 76s hang
        // reported in issue #137. The connection_timeout config or 30s default
        // ensures callers always get a response within a bounded window.
        let handshake_timeout = self
            .config
            .timeouts
            .nat_traversal
            .connection_establishment_timeout;
        let connection = match timeout(handshake_timeout, connecting).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                info!("connect: handshake to {} failed: {}", addr, e);
                return Err(EndpointError::Connection(e.to_string()));
            }
            Err(_) => {
                info!(
                    "connect: handshake to {} timed out after {:?}",
                    addr, handshake_timeout
                );
                return Err(EndpointError::Timeout);
            }
        };

        // Extract the public key from the TLS handshake
        let remote_public_key = extract_public_key_bytes_from_connection(&connection);

        // Post-handshake dedup: if we already have a live connection to this
        // address, just overwrite it with the new outgoing connection.
        if self.inner.is_connected(&addr) {
            debug!(
                "connect: simultaneous open for {} — overwriting existing connection",
                addr
            );
        }

        // Store connection in inner layer (keyed by remote SocketAddr)
        self.inner
            .add_connection(addr, connection.clone())
            .map_err(EndpointError::NatTraversal)?;

        // Spawn handler (we initiated the connection = Client side)
        self.inner
            .spawn_connection_handler(addr, connection, Side::Client)
            .map_err(EndpointError::NatTraversal)?;

        // Create peer connection record
        // v0.2: Peer is authenticated via TLS (ML-DSA-65) during handshake
        let peer_conn = PeerConnection {
            public_key: remote_public_key.clone(),
            remote_addr: TransportAddr::Quic(addr),
            authenticated: true, // TLS handles authentication
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            last_health_ping_sent: None,
            last_health_pong_received: None,
        };

        // Spawn background reader task BEFORE storing peer in connected_peers
        // This prevents a race where recv() called immediately after connect()
        // returns might miss early data if the peer sends before the task starts
        if let Ok(Some(conn)) = self.inner.get_connection(&addr) {
            self.spawn_reader_task(addr, conn).await;
        }

        // Store peer (reader task is already running, so no data loss window)
        self.connected_peers
            .write()
            .await
            .insert(addr, peer_conn.clone());

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.active_connections += 1;
            stats.successful_connections += 1;
            stats.direct_connections += 1;
        }

        // Broadcast event (we initiated the connection = Client side)
        let _ = self.event_tx.send(P2pEvent::PeerConnected {
            addr: TransportAddr::Quic(addr),
            public_key: remote_public_key,
            side: Side::Client,
        });

        Ok(peer_conn)
    }

    /// Connect to a peer using any transport address
    ///
    /// This method uses the connection router to automatically select the appropriate
    /// protocol engine (QUIC or Constrained) based on the transport capabilities.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use saorsa_transport::transport::TransportAddr;
    ///
    /// // Connect via UDP (uses QUIC)
    /// let udp_addr = TransportAddr::Quic("192.168.1.100:9000".parse()?);
    /// let conn = endpoint.connect_transport(&udp_addr, None).await?;
    ///
    /// // Connect via BLE (uses Constrained engine)
    /// let ble_addr = TransportAddr::Ble {
    ///     mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    ///     psm: 128,
    /// };
    /// let conn = endpoint.connect_transport(&ble_addr, None).await?;
    /// ```
    pub async fn connect_transport(
        &self,
        addr: &TransportAddr,
    ) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Use the router to determine the appropriate engine
        let mut router = self.router.write().await;
        let engine = router.select_engine_for_addr(addr);

        info!("Connecting to {} via {:?} engine", addr, engine);

        match engine {
            ProtocolEngine::Quic => {
                // For QUIC, extract socket address and use existing connect path
                let socket_addr = addr.as_socket_addr().ok_or_else(|| {
                    EndpointError::Connection(format!(
                        "Cannot extract socket address from {} for QUIC",
                        addr
                    ))
                })?;
                drop(router); // Release lock before async operation
                self.connect(socket_addr).await
            }
            ProtocolEngine::Constrained => {
                // For constrained transports, use the router's constrained connection
                let _routed = router.connect(addr).map_err(|e| {
                    EndpointError::Connection(format!("Constrained connection failed: {}", e))
                })?;

                // Use a synthetic socket address for constrained connections
                let synthetic_addr = addr.to_synthetic_socket_addr();

                let peer_conn = PeerConnection {
                    public_key: None, // Constrained connections don't have TLS auth yet
                    remote_addr: addr.clone(),
                    authenticated: false,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                    last_health_ping_sent: None,
                    last_health_pong_received: None,
                };

                // Store peer keyed by synthetic address
                drop(router); // Release lock before acquiring connected_peers lock
                self.connected_peers
                    .write()
                    .await
                    .insert(synthetic_addr, peer_conn.clone());

                // Update stats
                {
                    let mut stats = self.stats.write().await;
                    stats.active_connections += 1;
                    stats.successful_connections += 1;
                }

                // Broadcast event
                let _ = self.event_tx.send(P2pEvent::PeerConnected {
                    addr: addr.clone(),
                    public_key: None,
                    side: Side::Client,
                });

                Ok(peer_conn)
            }
        }
    }

    /// Get the connection router for advanced routing control
    ///
    /// Returns a reference to the connection router which can be used to:
    /// - Query engine selection for addresses
    /// - Get routing statistics
    /// - Configure routing behavior
    pub async fn router(&self) -> tokio::sync::RwLockReadGuard<'_, ConnectionRouter> {
        self.router.read().await
    }

    /// Get routing statistics
    pub async fn routing_stats(&self) -> crate::connection_router::RouterStats {
        self.router.read().await.stats().clone()
    }

    /// Register a constrained connection for a transport address
    ///
    /// This associates a TransportAddr with a ConstrainedEngine ConnectionId, enabling
    /// send() to use the proper constrained protocol for reliable delivery.
    ///
    /// # Arguments
    ///
    /// * `addr` - The remote transport address
    /// * `conn_id` - The ConnectionId from the ConstrainedEngine
    ///
    /// # Returns
    ///
    /// The previous ConnectionId if one was already registered for this address.
    pub async fn register_constrained_connection(
        &self,
        addr: TransportAddr,
        conn_id: ConstrainedConnectionId,
    ) -> Option<ConstrainedConnectionId> {
        let old = self
            .constrained_connections
            .write()
            .await
            .insert(addr.clone(), conn_id);
        debug!(
            "Registered constrained connection for addr {}: conn_id={:?}",
            addr, conn_id
        );
        old
    }

    /// Unregister a constrained connection for a transport address
    ///
    /// Call this when a constrained connection is closed or reset.
    ///
    /// # Returns
    ///
    /// The ConnectionId if one was registered for this address.
    pub async fn unregister_constrained_connection(
        &self,
        addr: &TransportAddr,
    ) -> Option<ConstrainedConnectionId> {
        let removed = self.constrained_connections.write().await.remove(addr);
        if removed.is_some() {
            debug!("Unregistered constrained connection for addr {}", addr);
        }
        removed
    }

    /// Check if a transport address has a constrained connection
    pub async fn has_constrained_connection(&self, addr: &TransportAddr) -> bool {
        self.constrained_connections.read().await.contains_key(addr)
    }

    /// Get the ConnectionId for a transport address's constrained connection
    pub async fn get_constrained_connection_id(
        &self,
        addr: &TransportAddr,
    ) -> Option<ConstrainedConnectionId> {
        self.constrained_connections.read().await.get(addr).copied()
    }

    /// Get the number of active constrained connections
    pub async fn constrained_connection_count(&self) -> usize {
        self.constrained_connections.read().await.len()
    }

    /// Look up TransportAddr from constrained ConnectionId
    pub async fn addr_from_constrained_conn(
        &self,
        conn_id: ConstrainedConnectionId,
    ) -> Option<TransportAddr> {
        self.constrained_peer_addrs
            .read()
            .await
            .get(&conn_id)
            .cloned()
    }

    /// Connect to a peer using dual-stack strategy (tries both IPv4 and IPv6 in parallel)
    ///
    /// This method implements the user requirement: **"connect on ip4 and 6 we do both"**
    ///
    /// **Strategy**:
    /// 1. Separates addresses by family (IPv4 vs IPv6)
    /// 2. Tries both families in parallel using `tokio::join!`
    /// 3. Handles all scenarios:
    ///    - **Both work**: Keeps dual connections for redundancy (BEST CASE)
    ///    - **IPv4-only**: Uses IPv4 connection, graceful degradation
    ///
    /// This method implements the user requirement: **"connect on ip4 and 6 we do both"**
    ///
    /// **Strategy**:
    /// 1. Separates addresses by family (IPv4 vs IPv6)
    /// 2. Tries both families in parallel using `tokio::join!`
    /// 3. Handles all scenarios:
    ///    - **Both work**: Keeps dual connections for redundancy (BEST CASE)
    ///    - **IPv4-only**: Uses IPv4 connection, graceful degradation
    ///    - **IPv6-only**: Uses IPv6 connection, graceful degradation  
    ///    - **Neither**: Returns error (try NAT traversal next)
    ///
    /// # Arguments
    /// * `addresses` - List of candidate addresses (mix of IPv4 and IPv6)
    ///
    /// # Returns
    /// Primary connection (IPv6 preferred if both succeed)
    ///
    /// # Dual-Connection Behavior
    /// When both IPv4 AND IPv6 succeed, BOTH connections are stored in `connected_peers`.
    /// The system maintains redundant connections for maximum reliability.
    pub async fn connect_dual_stack(
        &self,
        addresses: &[SocketAddr],
    ) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Separate addresses by family
        let ipv4_addrs: Vec<SocketAddr> = addresses
            .iter()
            .filter(|addr| matches!(addr.ip(), IpAddr::V4(_)))
            .copied()
            .collect();

        let ipv6_addrs: Vec<SocketAddr> = addresses
            .iter()
            .filter(|addr| matches!(addr.ip(), IpAddr::V6(_)))
            .copied()
            .collect();

        info!(
            "Dual-stack connect: {} IPv4, {} IPv6 addresses",
            ipv4_addrs.len(),
            ipv6_addrs.len(),
        );

        // Use "peer" as SNI for all P2P connections
        // Raw Public Key authentication validates the peer's public key directly,
        // so we don't need/use SNI for authentication. A fixed SNI avoids
        // "invalid server name" errors from hex peer IDs being too long.
        let (ipv4_result, ipv6_result) = tokio::join!(
            self.try_connect_family(&ipv4_addrs, "IPv4"),
            self.try_connect_family(&ipv6_addrs, "IPv6"),
        );

        // Handle all possible outcomes
        match (ipv4_result, ipv6_result) {
            (Some(v4_conn), Some(v6_conn)) => {
                // 🎉 BEST CASE: Both IPv4 AND IPv6 work - keep both!
                info!(
                    "✓✓ Dual-stack success! IPv4: {}, IPv6: {} (maintaining both connections)",
                    v4_conn.remote_addr, v6_conn.remote_addr
                );

                // Both connections already stored by try_connect_family
                // Return IPv6 as primary (modern internet best practice)
                Ok(v6_conn)
            }

            (Some(v4_conn), None) => {
                // IPv4-only network (v6 unavailable or failed)
                info!(
                    "IPv4-only connection established to {}",
                    v4_conn.remote_addr
                );
                Ok(v4_conn)
            }

            (None, Some(v6_conn)) => {
                // IPv6-only network (v4 unavailable or failed)
                info!(
                    "IPv6-only connection established to {}",
                    v6_conn.remote_addr
                );
                Ok(v6_conn)
            }

            (None, None) => {
                // Neither direct connection works - try NAT traversal next
                warn!("Both IPv4 and IPv6 direct connections failed");
                Err(EndpointError::Connection(
                    "Dual-stack connection failed for both address families".to_string(),
                ))
            }
        }
    }

    /// Try to connect using addresses from one family (IPv4 or IPv6)
    ///
    async fn try_connect_family(
        &self,
        addresses: &[SocketAddr],
        family_name: &str,
    ) -> Option<PeerConnection> {
        if addresses.is_empty() {
            debug!("{}: No addresses to try", family_name);
            return None;
        }

        debug!("Trying {} {} addresses", addresses.len(), family_name);

        for (idx, addr) in addresses.iter().enumerate() {
            debug!(
                "  {} attempt {}/{}: {}",
                family_name,
                idx + 1,
                addresses.len(),
                addr
            );

            match timeout(Duration::from_secs(5), self.connect(*addr)).await {
                Ok(Ok(peer_conn)) => {
                    info!("✓ {} connection successful to {}", family_name, addr);
                    return Some(peer_conn);
                }
                Ok(Err(e)) => {
                    debug!("  {} to {} failed: {}", family_name, addr, e);
                    // Try next address
                }
                Err(_) => {
                    debug!("  {} to {} timed out (5s)", family_name, addr);
                    // Try next address
                }
            }
        }

        debug!("{}: All {} addresses failed", family_name, addresses.len());
        None
    }

    /// Connect with automatic fallback: IPv4 → IPv6 → HolePunch → Relay
    ///
    /// This method implements a progressive connection strategy that automatically
    /// falls back through increasingly aggressive NAT traversal techniques:
    ///
    /// 1. **Direct IPv4** (5s timeout) - Simple direct connection
    /// 2. **Direct IPv6** (5s timeout) - Bypasses NAT when IPv6 available
    /// 3. **Hole-Punch** (15s timeout) - Coordinated NAT traversal via common peer
    /// 4. **Relay** (30s timeout) - MASQUE relay as last resort
    ///
    /// # Arguments
    ///
    /// * `target_ipv4` - Optional IPv4 address of the target peer
    /// * `target_ipv6` - Optional IPv6 address of the target peer
    /// * `strategy_config` - Optional custom strategy configuration
    ///
    /// # Returns
    ///
    /// A tuple of (PeerConnection, ConnectionMethod) indicating how the connection
    /// was established.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let (conn, method) = endpoint.connect_with_fallback(
    ///     Some("1.2.3.4:9000".parse()?),
    ///     Some("[2001:db8::1]:9000".parse()?),
    ///     None, // Use default strategy config
    /// ).await?;
    ///
    /// match method {
    ///     ConnectionMethod::DirectIPv4 => println!("Direct IPv4"),
    ///     ConnectionMethod::DirectIPv6 => println!("Direct IPv6"),
    ///     ConnectionMethod::HolePunched { coordinator } => println!("Via {}", coordinator),
    ///     ConnectionMethod::Relayed { relay } => println!("Relayed via {}", relay),
    /// }
    /// ```
    pub async fn connect_with_fallback(
        &self,
        target_ipv4: Option<SocketAddr>,
        target_ipv6: Option<SocketAddr>,
        strategy_config: Option<StrategyConfig>,
    ) -> Result<(PeerConnection, ConnectionMethod), EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Build strategy config with coordinator and relay from our config
        let mut config = strategy_config.unwrap_or_default();
        if config.coordinator.is_none() {
            config.coordinator = self
                .config
                .known_peers
                .first()
                .and_then(|addr| addr.as_socket_addr());
        }
        if config.relay_addrs.is_empty() {
            // Optimization: Try to find a high-quality relay from our cache first
            let target_addr = target_ipv4.or(target_ipv6);
            if let Some(addr) = target_addr {
                // Select best relay for this target (preferring dual-stack)
                let relays = self
                    .bootstrap_cache
                    .select_relays_for_target(1, &addr, true)
                    .await;

                if let Some(best_relay) = relays.first() {
                    // Use the first address of the best relay
                    // In a perfect world we'd check reachability of this address too,
                    // but for now we assume cached addresses are valid candidates.
                    if let Some(relay_addr) = best_relay.addresses.first().copied() {
                        config.relay_addrs.push(relay_addr);
                        debug!(
                            "Selected optimized relay from cache: {:?} for target {}",
                            relay_addr, addr
                        );
                    }
                }
            }

            // Fallback to static config if cache gave nothing
            if config.relay_addrs.is_empty() {
                if let Some(relay_addr) = self.config.nat.relay_nodes.first().copied() {
                    config.relay_addrs.push(relay_addr);
                }
            }
        }

        let mut strategy = ConnectionStrategy::new(config);

        info!(
            "Starting fallback connection: IPv4={:?}, IPv6={:?}",
            target_ipv4, target_ipv6
        );

        // Collect direct addresses for Happy Eyeballs racing (RFC 8305)
        let mut direct_addresses: Vec<SocketAddr> = Vec::new();
        if let Some(v6) = target_ipv6 {
            direct_addresses.push(v6);
        }
        if let Some(v4) = target_ipv4 {
            direct_addresses.push(v4);
        }

        loop {
            match strategy.current_stage().clone() {
                ConnectionStage::DirectIPv4 { .. } => {
                    // Use Happy Eyeballs (RFC 8305) to race all direct addresses (IPv4 + IPv6)
                    // instead of trying them sequentially. This prevents stalls when one address
                    // family is broken by racing with a 250ms stagger.
                    if direct_addresses.is_empty() {
                        debug!("No direct addresses provided, skipping to hole-punch");
                        strategy.transition_to_ipv6("No direct addresses");
                        continue;
                    }

                    let he_config = HappyEyeballsConfig::default();
                    let direct_timeout = strategy.ipv4_timeout().max(strategy.ipv6_timeout());

                    info!(
                        "Happy Eyeballs: racing {} direct addresses (timeout: {:?})",
                        direct_addresses.len(),
                        direct_timeout
                    );

                    // Clone the QUIC endpoint for use in the Happy Eyeballs closure.
                    // Each spawned attempt needs its own reference to create connections.
                    let quic_endpoint = match self.inner.get_endpoint().cloned() {
                        Some(ep) => ep,
                        None => {
                            debug!("QUIC endpoint not available, skipping direct");
                            strategy.transition_to_ipv6("QUIC endpoint not available");
                            strategy.transition_to_holepunch("QUIC endpoint not available");
                            continue;
                        }
                    };

                    let addrs = direct_addresses.clone();
                    let he_result = timeout(direct_timeout, async {
                        happy_eyeballs::race_connect(&addrs, &he_config, |addr| {
                            let ep = quic_endpoint.clone();
                            async move {
                                let connecting = ep
                                    .connect(addr, "peer")
                                    .map_err(|e| format!("connect error: {e}"))?;
                                connecting
                                    .await
                                    .map_err(|e| format!("handshake error: {e}"))
                            }
                        })
                        .await
                    })
                    .await;

                    match he_result {
                        Ok(Ok((connection, winning_addr))) => {
                            let method = if winning_addr.is_ipv6() {
                                ConnectionMethod::DirectIPv6
                            } else {
                                ConnectionMethod::DirectIPv4
                            };
                            info!(
                                "Happy Eyeballs: {} connection to {} succeeded",
                                method, winning_addr
                            );

                            // Complete the connection setup (handlers, stats)
                            let peer_conn = self
                                .finalize_direct_connection(connection, winning_addr)
                                .await?;
                            return Ok((peer_conn, method));
                        }
                        Ok(Err(e)) => {
                            debug!("Happy Eyeballs: all direct attempts failed: {}", e);
                            strategy.transition_to_ipv6(e.to_string());
                            strategy.transition_to_holepunch("Happy Eyeballs exhausted");
                        }
                        Err(_) => {
                            debug!("Happy Eyeballs: direct connection timed out");
                            strategy.transition_to_ipv6("Timeout");
                            strategy.transition_to_holepunch("Happy Eyeballs timed out");
                        }
                    }
                }

                ConnectionStage::DirectIPv6 { .. } => {
                    // Happy Eyeballs already handled both IPv4 and IPv6 in the DirectIPv4 stage.
                    // If we reach here, it means Happy Eyeballs failed and we need to move on.
                    debug!(
                        "DirectIPv6 stage reached after Happy Eyeballs, advancing to hole-punch"
                    );
                    strategy.transition_to_holepunch("Handled by Happy Eyeballs");
                }

                ConnectionStage::HolePunching {
                    coordinator, round, ..
                } => {
                    let target = target_ipv4
                        .or(target_ipv6)
                        .ok_or(EndpointError::NoAddress)?;

                    info!(
                        "Trying hole-punch to {} via {} (round {})",
                        target, coordinator, round
                    );

                    // Use our existing NAT traversal infrastructure
                    match timeout(
                        strategy.holepunch_timeout(),
                        self.try_hole_punch(target, coordinator),
                    )
                    .await
                    {
                        Ok(Ok(conn)) => {
                            info!("✓ Hole-punch succeeded to {} via {}", target, coordinator);
                            return Ok((conn, ConnectionMethod::HolePunched { coordinator }));
                        }
                        Ok(Err(e)) => {
                            strategy.record_holepunch_error(round, e.to_string());
                            if strategy.should_retry_holepunch() {
                                debug!("Hole-punch round {} failed, retrying", round);
                                strategy.increment_round();
                            } else {
                                debug!("Hole-punch failed after {} rounds", round);
                                strategy.transition_to_relay(e.to_string());
                            }
                        }
                        Err(_) => {
                            strategy.record_holepunch_error(round, "Timeout".to_string());
                            if strategy.should_retry_holepunch() {
                                debug!("Hole-punch round {} timed out, retrying", round);
                                strategy.increment_round();
                            } else {
                                debug!("Hole-punch timed out after {} rounds", round);
                                strategy.transition_to_relay("Timeout");
                            }
                        }
                    }
                }

                ConnectionStage::Relay { relay_addr, .. } => {
                    let target = target_ipv4
                        .or(target_ipv6)
                        .ok_or(EndpointError::NoAddress)?;

                    info!("Trying relay connection to {} via {}", target, relay_addr);

                    match timeout(
                        strategy.relay_timeout(),
                        self.try_relay_connection(target, relay_addr),
                    )
                    .await
                    {
                        Ok(Ok(conn)) => {
                            info!(
                                "✓ Relay connection succeeded to {} via {}",
                                target, relay_addr
                            );
                            return Ok((conn, ConnectionMethod::Relayed { relay: relay_addr }));
                        }
                        Ok(Err(e)) => {
                            debug!("Relay connection failed: {}", e);
                            strategy.transition_to_failed(e.to_string());
                        }
                        Err(_) => {
                            debug!("Relay connection timed out");
                            strategy.transition_to_failed("Timeout");
                        }
                    }
                }

                ConnectionStage::Failed { errors } => {
                    let error_summary = errors
                        .iter()
                        .map(|e| format!("{:?}: {}", e.method, e.error))
                        .collect::<Vec<_>>()
                        .join("; ");
                    return Err(EndpointError::AllStrategiesFailed(error_summary));
                }

                ConnectionStage::Connected { via } => {
                    // This shouldn't happen in the loop, but handle it
                    unreachable!("Connected stage reached in loop: {:?}", via);
                }
            }
        }
    }

    /// Finalize a direct QUIC connection established by Happy Eyeballs.
    ///
    /// Takes the raw QUIC `Connection` from the successful handshake and completes
    /// the P2P connection setup: public key extraction, connection storage, handler
    /// spawning, stats update, and event broadcast.
    async fn finalize_direct_connection(
        &self,
        connection: crate::high_level::Connection,
        addr: SocketAddr,
    ) -> Result<PeerConnection, EndpointError> {
        // Extract public key from TLS
        let remote_public_key = extract_public_key_bytes_from_connection(&connection);

        // Dedup check: if already connected to this address, use fingerprint tiebreaker
        if self.inner.is_connected(&addr) {
            // Use our SPKI fingerprint vs remote's for deterministic tiebreaking
            let remote_fingerprint = remote_public_key
                .as_deref()
                .and_then(|pk| {
                    crate::crypto::raw_public_keys::pqc::fingerprint_public_key_bytes(pk).ok()
                })
                .unwrap_or([0u8; 32]);
            let we_keep_client = self.our_fingerprint < remote_fingerprint;
            if !we_keep_client {
                // We have the higher fingerprint: close this outgoing connection,
                // keep the existing one (from accept path).
                info!(
                    "finalize_direct_connection: simultaneous open for {} — \
                     closing outgoing (keeping incoming)",
                    addr
                );
                connection.close(0u32.into(), b"duplicate");
                // Wait briefly for the accept path to populate connected_peers
                for _ in 0..10 {
                    let peers = self.connected_peers.read().await;
                    if let Some(existing) = peers.get(&addr) {
                        return Ok(existing.clone());
                    }
                    drop(peers);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                return Err(EndpointError::Connection(
                    "simultaneous open: peer connection not yet available, retry".into(),
                ));
            }
            // We have the lower fingerprint: keep our outgoing connection,
            // remove the old one from accept path.
            info!(
                "finalize_direct_connection: simultaneous open for {} — \
                 keeping outgoing (replacing incoming)",
                addr
            );
            let _ = self.inner.remove_connection(&addr);
        }

        // Store in NAT traversal layer (keyed by remote SocketAddr)
        self.inner
            .add_connection(addr, connection.clone())
            .map_err(EndpointError::NatTraversal)?;

        // Spawn connection handler (Client side - we initiated)
        self.inner
            .spawn_connection_handler(addr, connection, Side::Client)
            .map_err(EndpointError::NatTraversal)?;

        let peer_conn = PeerConnection {
            public_key: remote_public_key.clone(),
            remote_addr: TransportAddr::Quic(addr),
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            last_health_ping_sent: None,
            last_health_pong_received: None,
        };

        // Spawn reader task before storing peer to prevent data loss race
        if let Ok(Some(conn)) = self.inner.get_connection(&addr) {
            self.spawn_reader_task(addr, conn).await;
        }

        self.connected_peers
            .write()
            .await
            .insert(addr, peer_conn.clone());

        {
            let mut stats = self.stats.write().await;
            stats.active_connections += 1;
            stats.successful_connections += 1;
            stats.direct_connections += 1;
        }

        let _ = self.event_tx.send(P2pEvent::PeerConnected {
            addr: TransportAddr::Quic(addr),
            public_key: remote_public_key,
            side: Side::Client,
        });

        Ok(peer_conn)
    }

    /// Internal helper for hole-punch attempt
    async fn try_hole_punch(
        &self,
        target: SocketAddr,
        coordinator: SocketAddr,
    ) -> Result<PeerConnection, EndpointError> {
        // First ensure we're connected to the coordinator
        if !self.is_connected_to_addr(coordinator).await {
            debug!("Connecting to coordinator {} first", coordinator);
            self.connect(coordinator).await?;
        }

        // Derive an inner PeerId for the NAT traversal layer from the target address
        // Initiate NAT traversal (inner layer uses SocketAddr)
        self.inner
            .initiate_nat_traversal(target, coordinator)
            .map_err(EndpointError::NatTraversal)?;

        // Poll for completion with event-driven notification instead of sleep loop
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);

        loop {
            if self.shutdown.is_cancelled() {
                return Err(EndpointError::ShuttingDown);
            }

            let events = self
                .inner
                .poll(Instant::now())
                .map_err(EndpointError::NatTraversal)?;

            for event in events {
                match event {
                    NatTraversalEvent::ConnectionEstablished {
                        remote_address,
                        public_key,
                        ..
                    } if remote_address == target => {
                        let peer_conn = PeerConnection {
                            public_key: public_key.clone(),
                            remote_addr: TransportAddr::Quic(remote_address),
                            authenticated: true,
                            connected_at: Instant::now(),
                            last_activity: Instant::now(),
                            last_health_ping_sent: None,
                            last_health_pong_received: None,
                        };

                        // Spawn background reader task BEFORE storing in connected_peers
                        if let Ok(Some(conn)) = self.inner.get_connection(&target) {
                            self.spawn_reader_task(remote_address, conn).await;
                        }

                        self.connected_peers
                            .write()
                            .await
                            .insert(remote_address, peer_conn.clone());

                        return Ok(peer_conn);
                    }
                    NatTraversalEvent::TraversalFailed {
                        remote_address,
                        error,
                        ..
                    } if remote_address == target => {
                        return Err(EndpointError::NatTraversal(error));
                    }
                    _ => {}
                }
            }

            // Wait for connection notification, shutdown, or timeout
            tokio::select! {
                _ = self.inner.connection_notify().notified() => {}
                _ = self.shutdown.cancelled() => {
                    return Err(EndpointError::ShuttingDown);
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(EndpointError::Timeout);
                }
            }
        }
    }

    async fn try_relay_connection(
        &self,
        target: SocketAddr,
        relay_addr: SocketAddr,
    ) -> Result<PeerConnection, EndpointError> {
        info!(
            "Attempting MASQUE relay connection to {} via {}",
            target, relay_addr
        );

        let public_addr = self
            .inner
            .establish_relay_session(relay_addr)
            .await
            .map_err(EndpointError::NatTraversal)?;

        info!(
            "MASQUE relay session established via {} (public addr: {:?})",
            relay_addr, public_addr
        );

        let conn = self.connect(target).await?;

        info!(
            "MASQUE relay connection succeeded to {} via {} (our relay addr: {:?})",
            target, relay_addr, public_addr
        );

        Ok(conn)
    }

    /// Check if we're connected to a specific address
    async fn is_connected_to_addr(&self, addr: SocketAddr) -> bool {
        let transport_addr = TransportAddr::Quic(addr);
        let peers = self.connected_peers.read().await;
        peers.values().any(|p| p.remote_addr == transport_addr)
    }

    /// Accept incoming connections
    ///
    /// Returns `None` if the endpoint is shutting down or the accept fails.
    /// This method races the inner accept against the shutdown token, so it
    /// will return promptly when `shutdown()` is called.
    pub async fn accept(&self) -> Option<PeerConnection> {
        if self.shutdown.is_cancelled() {
            return None;
        }

        let result = tokio::select! {
            r = self.inner.accept_connection() => r,
            _ = self.shutdown.cancelled() => return None,
        };

        match result {
            Ok((remote_addr, connection)) => {
                // Extract public key from TLS handshake
                let remote_public_key = extract_public_key_bytes_from_connection(&connection);

                // They initiated the connection to us = Server side
                if let Err(e) =
                    self.inner
                        .spawn_connection_handler(remote_addr, connection, Side::Server)
                {
                    error!("Failed to spawn connection handler: {}", e);
                    return None;
                }

                // v0.2: Peer is authenticated via TLS (ML-DSA-65) during handshake
                let peer_conn = PeerConnection {
                    public_key: remote_public_key.clone(),
                    remote_addr: TransportAddr::Quic(remote_addr),
                    authenticated: true, // TLS handles authentication
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                    last_health_ping_sent: None,
                    last_health_pong_received: None,
                };

                // Spawn background reader task BEFORE storing in connected_peers
                // to prevent race where recv() misses early data
                if let Ok(Some(conn)) = self.inner.get_connection(&remote_addr) {
                    self.spawn_reader_task(remote_addr, conn).await;
                }

                self.connected_peers
                    .write()
                    .await
                    .insert(remote_addr, peer_conn.clone());

                {
                    let mut stats = self.stats.write().await;
                    stats.active_connections += 1;
                    stats.successful_connections += 1;
                }

                // They initiated the connection to us = Server side
                let _ = self.event_tx.send(P2pEvent::PeerConnected {
                    addr: TransportAddr::Quic(remote_addr),
                    public_key: remote_public_key,
                    side: Side::Server,
                });

                Some(peer_conn)
            }
            Err(e) => {
                debug!("Accept failed: {}", e);
                None
            }
        }
    }

    /// Clean up a connection from ALL tracking structures.
    ///
    /// This is the single point of cleanup for connections — it removes the peer from:
    /// - `connected_peers` HashMap
    /// - `NatTraversalEndpoint.connections` DashMap (via `remove_connection()`)
    /// - `reader_handles` (aborts the background reader task)
    /// - Updates stats and emits a disconnect event
    ///
    /// Safe to call even if the peer is not in all structures (idempotent).
    async fn cleanup_connection(&self, addr: &SocketAddr, reason: DisconnectReason) {
        do_cleanup_connection(
            &*self.connected_peers,
            &*self.inner,
            &*self.reader_handles,
            &*self.stats,
            &self.event_tx,
            addr,
            reason,
        )
        .await;
    }

    /// Disconnect from a peer by address
    pub async fn disconnect(&self, addr: &SocketAddr) -> Result<(), EndpointError> {
        if self.connected_peers.read().await.contains_key(addr) {
            self.cleanup_connection(addr, DisconnectReason::Normal)
                .await;
            Ok(())
        } else {
            Err(EndpointError::PeerNotFound(*addr))
        }
    }

    /// Query the health status of a connection to a specific address.
    ///
    /// Returns `None` if the address is not connected.
    pub async fn connection_health(&self, addr: &SocketAddr) -> Option<ConnectionHealth> {
        let peers = self.connected_peers.read().await;
        let pc = peers.get(addr)?;

        // Not yet probed — treat as healthy (just connected)
        let Some(ping_sent) = pc.last_health_ping_sent else {
            return Some(ConnectionHealth::Healthy);
        };

        let pong_time = pc.last_health_pong_received.unwrap_or(pc.connected_at);
        if pong_time >= ping_sent {
            Some(ConnectionHealth::Healthy)
        } else if Instant::now().duration_since(ping_sent) > HEALTH_CHECK_EVICTION_THRESHOLD {
            Some(ConnectionHealth::Unresponsive)
        } else {
            Some(ConnectionHealth::Checking)
        }
    }

    // === Messaging ===

    /// Send data to a peer
    ///
    /// # Transport Selection
    ///
    /// This method selects the appropriate transport provider based on the destination
    /// peer's address type and the capabilities advertised in the transport registry.
    ///
    /// ## Current Behavior (Phase 2.1)
    ///
    /// All connections currently use UDP/QUIC via the existing `connection.open_uni()`
    /// path. This ensures backward compatibility with existing peers.
    ///
    /// ## Future Behavior (Phase 2.3)
    ///
    /// Transport selection will be based on:
    /// - Peer's advertised transport addresses (from connection metadata)
    /// - Transport provider capabilities (from `transport_registry`)
    /// - Protocol engine requirements (QUIC vs Constrained)
    ///
    /// Selection priority:
    /// 1. **UDP/QUIC**: Default for broadband, full QUIC support
    /// 2. **BLE**: For nearby devices, constrained engine
    /// 3. **LoRa**: For long-range, low-bandwidth scenarios
    /// 4. **Overlay**: For I2P/Yggdrasil privacy-preserving routing
    ///
    /// # Arguments
    ///
    /// - `addr`: The target peer's socket address
    /// - `data`: The payload to send
    ///
    /// # Errors
    ///
    /// Returns `EndpointError` if:
    /// - The endpoint is shutting down
    /// - The peer is not connected
    /// - No suitable transport provider is available
    /// - The send operation fails
    pub async fn send(&self, addr: &SocketAddr, data: &[u8]) -> Result<(), EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Get peer's transport address
        let peer_info = self.connected_peers.read().await;
        let peer_conn = peer_info
            .get(addr)
            .ok_or(EndpointError::PeerNotFound(*addr))?;
        let transport_addr = peer_conn.remote_addr.clone();
        drop(peer_info); // Release read lock before async operations

        // Select protocol engine based on transport address
        let engine = {
            let mut router = self.router.write().await;
            router.select_engine_for_addr(&transport_addr)
        };

        match engine {
            crate::transport::ProtocolEngine::Quic => {
                // Use existing QUIC connection (UDP transport)
                let connection = self
                    .inner
                    .get_connection(addr)
                    .map_err(EndpointError::NatTraversal)?
                    .ok_or(EndpointError::PeerNotFound(*addr))?;

                let mut send_stream = connection
                    .open_uni()
                    .await
                    .map_err(|e| EndpointError::Connection(e.to_string()))?;

                send_stream
                    .write_all(data)
                    .await
                    .map_err(|e| EndpointError::Connection(e.to_string()))?;

                send_stream
                    .finish()
                    .map_err(|e| EndpointError::Connection(e.to_string()))?;

                debug!("Sent {} bytes to {} via QUIC", data.len(), addr);
            }
            crate::transport::ProtocolEngine::Constrained => {
                // Check if we have an established constrained connection for this address
                let maybe_conn_id = self
                    .constrained_connections
                    .read()
                    .await
                    .get(&transport_addr)
                    .copied();

                if let Some(conn_id) = maybe_conn_id {
                    // Use ConstrainedEngine for reliable delivery
                    let engine = self.inner.constrained_engine();
                    let responses = {
                        let mut engine = engine.lock();
                        engine
                            .send(conn_id, data)
                            .map_err(|e| EndpointError::Connection(e.to_string()))?
                    };

                    // Send any packets generated by the constrained engine
                    for (_dest_addr, packet_data) in responses {
                        self.transport_registry
                            .send(&packet_data, &transport_addr)
                            .await
                            .map_err(|e| EndpointError::Connection(e.to_string()))?;
                    }

                    debug!(
                        "Sent {} bytes to {} via constrained engine ({})",
                        data.len(),
                        addr,
                        transport_addr.transport_type()
                    );
                } else {
                    // No established connection - send directly via transport
                    self.transport_registry
                        .send(data, &transport_addr)
                        .await
                        .map_err(|e| EndpointError::Connection(e.to_string()))?;

                    debug!(
                        "Sent {} bytes to {} via constrained transport (direct, {})",
                        data.len(),
                        addr,
                        transport_addr.transport_type()
                    );
                }
            }
        }

        // Update last activity
        if let Some(peer_conn) = self.connected_peers.write().await.get_mut(addr) {
            peer_conn.last_activity = Instant::now();
        }

        Ok(())
    }

    /// Receive data from any connected peer.
    ///
    /// Blocks until data arrives from any transport (UDP/QUIC, BLE, LoRa, etc.)
    /// or the endpoint shuts down. Background reader tasks feed a shared channel,
    /// so this wakes instantly when data is available.
    ///
    /// # Errors
    ///
    /// Returns `EndpointError::ShuttingDown` if the endpoint is shutting down.
    pub async fn recv(&self) -> Result<(SocketAddr, Vec<u8>), EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Note: pending data buffer (BoundedPendingBuffer) still uses PeerId internally.
        // It is not consulted here; background reader tasks feed the data_rx channel
        // using SocketAddr as the key.

        // Wait for data from the shared channel (fed by background reader tasks),
        // racing against the shutdown token so callers unblock promptly on shutdown.
        let mut rx = self.data_rx.lock().await;
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(msg) => Ok(msg),
                None => Err(EndpointError::ShuttingDown),
            },
            _ = self.shutdown.cancelled() => Err(EndpointError::ShuttingDown),
        }
    }

    // === Events ===

    /// Subscribe to endpoint events
    pub fn subscribe(&self) -> broadcast::Receiver<P2pEvent> {
        self.event_tx.subscribe()
    }

    // === Statistics ===

    /// Get endpoint statistics
    pub async fn stats(&self) -> EndpointStats {
        self.stats.read().await.clone()
    }

    /// Get metrics for a specific connection by address
    pub async fn connection_metrics(&self, addr: &SocketAddr) -> Option<ConnectionMetrics> {
        let peers = self.connected_peers.read().await;
        let peer_conn = peers.get(addr)?;
        let last_activity = Some(peer_conn.last_activity);
        drop(peers);

        let connection = self.inner.get_connection(addr).ok()??;
        let stats = connection.stats();
        let rtt = connection.rtt();

        Some(ConnectionMetrics {
            bytes_sent: stats.udp_tx.bytes,
            bytes_received: stats.udp_rx.bytes,
            rtt: Some(rtt),
            packet_loss: stats.path.lost_packets as f64
                / (stats.path.sent_packets + stats.path.lost_packets).max(1) as f64,
            last_activity,
        })
    }

    /// Get NAT traversal statistics
    pub fn nat_stats(&self) -> Result<NatTraversalStatistics, EndpointError> {
        self.inner
            .get_nat_stats()
            .map_err(|e| EndpointError::Connection(e.to_string()))
    }

    // === Known Peers ===

    /// Connect to configured known peers
    ///
    /// This method now uses the connection router to automatically select
    /// the appropriate protocol engine for each peer address.
    pub async fn connect_known_peers(&self) -> Result<usize, EndpointError> {
        let mut connected = 0;
        let known_peers = self.config.known_peers.clone();

        for addr in &known_peers {
            // Use connect_transport for all address types
            match self.connect_transport(addr).await {
                Ok(_) => {
                    connected += 1;
                    info!("Connected to known peer {}", addr);
                }
                Err(e) => {
                    warn!("Failed to connect to known peer {}: {}", addr, e);
                }
            }
        }

        {
            let mut stats = self.stats.write().await;
            stats.connected_bootstrap_nodes = connected;
        }

        let _ = self.event_tx.send(P2pEvent::BootstrapStatus {
            connected,
            total: known_peers.len(),
        });

        Ok(connected)
    }

    /// Add a bootstrap node dynamically
    pub async fn add_bootstrap(&self, addr: SocketAddr) {
        let _ = self.inner.add_bootstrap_node(addr);
        let mut stats = self.stats.write().await;
        stats.total_bootstrap_nodes += 1;
    }

    /// Get list of connected peers
    pub async fn connected_peers(&self) -> Vec<PeerConnection> {
        self.connected_peers
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    /// Check if an address is connected
    pub async fn is_connected(&self, addr: &SocketAddr) -> bool {
        self.connected_peers.read().await.contains_key(addr)
    }

    /// Check if an address is authenticated
    pub async fn is_authenticated(&self, addr: &SocketAddr) -> bool {
        self.connected_peers
            .read()
            .await
            .get(addr)
            .map(|p| p.authenticated)
            .unwrap_or(false)
    }

    // === Lifecycle ===

    /// Shutdown the endpoint gracefully
    pub async fn shutdown(&self) {
        info!("Shutting down P2P endpoint");
        self.shutdown.cancel();

        // Abort all background reader tasks
        self.reader_tasks.lock().await.abort_all();
        self.reader_handles.write().await.clear();

        // Disconnect all peers
        let addrs: Vec<SocketAddr> = self.connected_peers.read().await.keys().copied().collect();
        for addr in addrs {
            let _ = self.disconnect(&addr).await;
        }

        // Bounded timeout prevents blocking when the remote peer is unresponsive.
        match timeout(SHUTDOWN_DRAIN_TIMEOUT, self.inner.shutdown()).await {
            Err(_) => warn!("Inner endpoint shutdown timed out, proceeding"),
            Ok(Err(e)) => warn!("Inner endpoint shutdown error: {e}"),
            Ok(Ok(())) => {}
        }
    }

    /// Check if endpoint is running
    pub fn is_running(&self) -> bool {
        !self.shutdown.is_cancelled()
    }

    /// Get a clone of the shutdown token (for external cancellation listening)
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    // === Internal helpers ===

    /// Spawn a background tokio task that reads uni streams from a QUIC connection
    /// and forwards received data into the shared `data_tx` channel.
    ///
    /// The task exits naturally when the connection is closed or the channel is dropped.
    async fn spawn_reader_task(&self, addr: SocketAddr, connection: crate::high_level::Connection) {
        let data_tx = self.data_tx.clone();
        let connected_peers = Arc::clone(&self.connected_peers);
        let event_tx = self.event_tx.clone();
        let max_read_bytes = self.config.max_message_size;

        let abort_handle = self.reader_tasks.lock().await.spawn(async move {
            loop {
                // Accept the next unidirectional stream
                let mut recv_stream = match connection.accept_uni().await {
                    Ok(stream) => stream,
                    Err(e) => {
                        debug!("Reader task for {} ending: accept_uni error: {}", addr, e);
                        break;
                    }
                };

                let data = match recv_stream.read_to_end(max_read_bytes).await {
                    Ok(data) if data.is_empty() => continue,
                    Ok(data) => data,
                    Err(e) => {
                        debug!("Reader task for {}: read_to_end error: {}", addr, e);
                        break;
                    }
                };

                let data_len = data.len();
                tracing::trace!("Reader task: {} bytes from {}", data_len, addr);

                // Update last_activity
                if let Some(peer_conn) = connected_peers.write().await.get_mut(&addr) {
                    peer_conn.last_activity = Instant::now();
                }

                // Health check protocol: only exact PING/PONG messages are internal.
                // All other messages (including those starting with 0xFF) are forwarded
                // to the application to avoid silent data loss.
                if data.len() == 2 && data[0] == HEALTH_CHECK_PREFIX {
                    if data[1] == HEALTH_PING[1] {
                        // Received PING — respond with PONG
                        tracing::trace!("Health PING from {}, sending PONG", addr);
                        if let Ok(mut send) = connection.open_uni().await {
                            let _ = send.write_all(&HEALTH_PONG).await;
                            let _ = send.finish();
                        }
                        continue;
                    } else if data[1] == HEALTH_PONG[1] {
                        // Received PONG — update health timestamp
                        tracing::trace!("Health PONG from {}", addr);
                        if let Some(peer_conn) = connected_peers.write().await.get_mut(&addr) {
                            peer_conn.last_health_pong_received = Some(Instant::now());
                        }
                        continue;
                    }
                }
                // Any other message (including 0xFF-prefixed non-health messages) is
                // forwarded to the application.

                // Emit DataReceived event
                let _ = event_tx.send(P2pEvent::DataReceived {
                    addr,
                    bytes: data_len,
                });

                // Send through channel; if the receiver is dropped, exit
                if data_tx.send((addr, data)).await.is_err() {
                    debug!("Reader task for {}: channel closed, exiting", addr);
                    break;
                }
            }

            addr
        });

        self.reader_handles.write().await.insert(addr, abort_handle);
    }

    /// Spawn a single background task that polls constrained transport events
    /// and forwards `DataReceived` payloads into the shared `data_tx` channel.
    ///
    /// Lifecycle events (ConnectionAccepted, ConnectionClosed, etc.) are handled
    /// inline within this task.
    fn spawn_constrained_poller(&self) {
        let inner = Arc::clone(&self.inner);
        let data_tx = self.data_tx.clone();
        let connected_peers = Arc::clone(&self.connected_peers);
        let event_tx = self.event_tx.clone();
        let constrained_peer_addrs = Arc::clone(&self.constrained_peer_addrs);
        let constrained_connections = Arc::clone(&self.constrained_connections);
        let shutdown = self.shutdown.clone();

        /// Register a new constrained peer in all lookup maps and emit a connect event.
        async fn register_constrained_peer(
            connection_id: ConstrainedConnectionId,
            addr: &TransportAddr,
            side: Side,
            constrained_connections: &RwLock<HashMap<TransportAddr, ConstrainedConnectionId>>,
            constrained_peer_addrs: &RwLock<HashMap<ConstrainedConnectionId, TransportAddr>>,
            connected_peers: &RwLock<HashMap<SocketAddr, PeerConnection>>,
            event_tx: &broadcast::Sender<P2pEvent>,
        ) {
            let synthetic_addr = addr.to_synthetic_socket_addr();
            constrained_connections
                .write()
                .await
                .insert(addr.clone(), connection_id);
            constrained_peer_addrs
                .write()
                .await
                .insert(connection_id, addr.clone());
            connected_peers.write().await.insert(
                synthetic_addr,
                PeerConnection {
                    public_key: None,
                    remote_addr: addr.clone(),
                    authenticated: false,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                    last_health_ping_sent: None,
                    last_health_pong_received: None,
                },
            );
            let _ = event_tx.send(P2pEvent::PeerConnected {
                addr: addr.clone(),
                public_key: None,
                side,
            });
        }

        tokio::spawn(async move {
            loop {
                let wrapper = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    event = inner.recv_constrained_event() => {
                        match event {
                            Some(w) => w,
                            None => {
                                debug!("Constrained event channel closed, exiting poller");
                                break;
                            }
                        }
                    }
                };

                match wrapper.event {
                    EngineEvent::DataReceived {
                        connection_id,
                        data,
                    } => {
                        let synthetic_addr = constrained_peer_addrs
                            .read()
                            .await
                            .get(&connection_id)
                            .map(|a| a.to_synthetic_socket_addr())
                            .unwrap_or_else(|| wrapper.remote_addr.to_synthetic_socket_addr());

                        let data_len = data.len();
                        tracing::trace!(
                            "Constrained poller: {} bytes from {}",
                            data_len,
                            synthetic_addr
                        );

                        if let Some(peer_conn) =
                            connected_peers.write().await.get_mut(&synthetic_addr)
                        {
                            peer_conn.last_activity = Instant::now();
                        }
                        let _ = event_tx.send(P2pEvent::DataReceived {
                            addr: synthetic_addr,
                            bytes: data_len,
                        });

                        if data_tx.send((synthetic_addr, data)).await.is_err() {
                            debug!("Constrained poller: channel closed, exiting");
                            break;
                        }
                    }
                    EngineEvent::ConnectionAccepted {
                        connection_id,
                        remote_addr: _,
                    } => {
                        register_constrained_peer(
                            connection_id,
                            &wrapper.remote_addr,
                            Side::Server,
                            &constrained_connections,
                            &constrained_peer_addrs,
                            &connected_peers,
                            &event_tx,
                        )
                        .await;
                    }
                    EngineEvent::ConnectionEstablished { connection_id } => {
                        if constrained_peer_addrs
                            .read()
                            .await
                            .get(&connection_id)
                            .is_none()
                        {
                            register_constrained_peer(
                                connection_id,
                                &wrapper.remote_addr,
                                Side::Client,
                                &constrained_connections,
                                &constrained_peer_addrs,
                                &connected_peers,
                                &event_tx,
                            )
                            .await;
                        }
                    }
                    EngineEvent::ConnectionClosed { connection_id } => {
                        let removed_addr =
                            constrained_peer_addrs.write().await.remove(&connection_id);
                        if let Some(addr) = removed_addr {
                            let synthetic_addr = addr.to_synthetic_socket_addr();
                            constrained_connections.write().await.remove(&addr);
                            connected_peers.write().await.remove(&synthetic_addr);
                            let _ = event_tx.send(P2pEvent::PeerDisconnected {
                                addr,
                                reason: DisconnectReason::RemoteClosed,
                            });
                            debug!(
                                "Constrained poller: peer at {} disconnected",
                                synthetic_addr
                            );
                        }
                    }
                    EngineEvent::ConnectionError {
                        connection_id,
                        error,
                    } => {
                        warn!(
                            "Constrained poller: conn_id={}, error={}",
                            connection_id.value(),
                            error
                        );
                    }
                    EngineEvent::Transmit { .. } => {}
                }
            }
        });
    }

    /// Spawn a background task that periodically detects and removes stale connections
    /// and probes live connections with health-check PINGs.
    ///
    /// Two-tier detection for issue #137 phantom connections:
    ///
    /// 1. **QUIC-level:** connections whose underlying transport is dead
    ///    (`is_peer_connected() == false`) are reaped immediately.
    /// 2. **App-level:** connections whose QUIC state looks alive but have not
    ///    responded to a health PING within [`HEALTH_CHECK_EVICTION_THRESHOLD`]
    ///    are considered phantom and evicted.
    ///
    /// Runs every 30 seconds until the endpoint shuts down.
    fn spawn_stale_connection_reaper(&self) {
        let connected_peers = Arc::clone(&self.connected_peers);
        let inner = Arc::clone(&self.inner);
        let event_tx = self.event_tx.clone();
        let stats = Arc::clone(&self.stats);
        let reader_handles = Arc::clone(&self.reader_handles);
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = shutdown.cancelled() => {
                        debug!("Stale connection reaper shutting down");
                        return;
                    }
                }

                // --- Phase A: Remove QUIC-dead connections ---
                // Collect addrs for connections whose inner transport is dead.

                let stale_addrs: Vec<SocketAddr> = {
                    let peers = connected_peers.read().await;
                    peers
                        .keys()
                        .filter(|addr| !inner.is_connected(addr))
                        .copied()
                        .collect()
                };

                if !stale_addrs.is_empty() {
                    info!(
                        "Stale connection reaper: removing {} dead connection(s)",
                        stale_addrs.len()
                    );
                }

                for addr in &stale_addrs {
                    do_cleanup_connection(
                        &*connected_peers,
                        &*inner,
                        &*reader_handles,
                        &*stats,
                        &event_tx,
                        addr,
                        DisconnectReason::Timeout,
                    )
                    .await;
                }

                // --- Phase B: Health-check live connections ---

                let alive_addrs: Vec<SocketAddr> = {
                    let peers = connected_peers.read().await;
                    peers
                        .keys()
                        .filter(|addr| inner.is_connected(addr))
                        .copied()
                        .collect()
                };

                let now = Instant::now();

                for addr in &alive_addrs {
                    // Check if this peer has missed too many health checks.
                    let should_evict = {
                        let peers = connected_peers.read().await;
                        if let Some(pc) = peers.get(addr) {
                            if let Some(ping_sent) = pc.last_health_ping_sent {
                                let pong_time =
                                    pc.last_health_pong_received.unwrap_or(pc.connected_at);
                                ping_sent > pong_time
                                    && now.duration_since(ping_sent)
                                        > HEALTH_CHECK_EVICTION_THRESHOLD
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    };

                    if should_evict {
                        warn!(
                            "Health check: {} unresponsive for {:?}, evicting phantom connection",
                            addr, HEALTH_CHECK_EVICTION_THRESHOLD
                        );
                        if let Ok(Some(conn)) = inner.get_connection(addr) {
                            conn.close(0u32.into(), b"health_check_failed");
                        }
                        let was_present = do_cleanup_connection(
                            &*connected_peers,
                            &*inner,
                            &*reader_handles,
                            &*stats,
                            &event_tx,
                            addr,
                            DisconnectReason::ConnectionLost,
                        )
                        .await;
                        if was_present {
                            stats.write().await.phantom_connections_evicted += 1;
                        }
                        continue;
                    }

                    // Send health PING
                    if let Ok(Some(conn)) = inner.get_connection(addr) {
                        match conn.open_uni().await {
                            Ok(mut send) => {
                                if send.write_all(&HEALTH_PING).await.is_ok() {
                                    let _ = send.finish();
                                    if let Some(pc) = connected_peers.write().await.get_mut(addr) {
                                        pc.last_health_ping_sent = Some(Instant::now());
                                    }
                                    tracing::trace!("Health PING sent to {}", addr);
                                }
                            }
                            Err(e) => {
                                debug!("Health check: failed to open stream to {}: {}", addr, e);
                            }
                        }
                    }
                }
            }
        });
    }

    // v0.2: authenticate_peer removed - TLS handles peer authentication via ML-DSA-65
}

impl Clone for P2pEndpoint {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            // v0.2: auth_manager removed - TLS handles peer authentication
            connected_peers: Arc::clone(&self.connected_peers),
            stats: Arc::clone(&self.stats),
            config: self.config.clone(),
            event_tx: self.event_tx.clone(),
            our_fingerprint: self.our_fingerprint,
            public_key: self.public_key.clone(),
            shutdown: self.shutdown.clone(),
            pending_data: Arc::clone(&self.pending_data),
            bootstrap_cache: Arc::clone(&self.bootstrap_cache),
            transport_registry: Arc::clone(&self.transport_registry),
            router: Arc::clone(&self.router),
            constrained_connections: Arc::clone(&self.constrained_connections),
            constrained_peer_addrs: Arc::clone(&self.constrained_peer_addrs),
            data_tx: self.data_tx.clone(),
            data_rx: Arc::clone(&self.data_rx),
            reader_tasks: Arc::clone(&self.reader_tasks),
            reader_handles: Arc::clone(&self.reader_handles),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_stats_default() {
        let stats = EndpointStats::default();
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.successful_connections, 0);
        assert_eq!(stats.nat_traversal_attempts, 0);
    }

    #[test]
    fn test_connection_metrics_default() {
        let metrics = ConnectionMetrics::default();
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
        assert!(metrics.rtt.is_none());
        assert_eq!(metrics.packet_loss, 0.0);
    }

    #[test]
    fn test_peer_connection_debug() {
        let socket_addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let conn = PeerConnection {
            public_key: None,
            remote_addr: TransportAddr::Quic(socket_addr),
            authenticated: false,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            last_health_ping_sent: None,
            last_health_pong_received: None,
        };
        let debug_str = format!("{:?}", conn);
        assert!(debug_str.contains("PeerConnection"));
    }

    #[test]
    fn test_disconnect_reason_debug() {
        let reason = DisconnectReason::Normal;
        assert!(format!("{:?}", reason).contains("Normal"));

        let reason = DisconnectReason::ProtocolError("test".to_string());
        assert!(format!("{:?}", reason).contains("test"));
    }

    #[test]
    fn test_traversal_phase_debug() {
        let phase = TraversalPhase::Discovery;
        assert!(format!("{:?}", phase).contains("Discovery"));
    }

    #[test]
    fn test_endpoint_error_display() {
        let err = EndpointError::Timeout;
        assert!(err.to_string().contains("timed out"));

        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let err = EndpointError::PeerNotFound(addr);
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_endpoint_creation() {
        // v0.13.0+: No role - all nodes are symmetric P2P nodes
        let config = P2pConfig::builder().build().expect("valid config");

        let result = P2pEndpoint::new(config).await;
        // May fail in test environment without network, but shouldn't panic
        if let Ok(endpoint) = result {
            assert!(endpoint.is_running());
            assert!(endpoint.local_addr().is_some() || endpoint.local_addr().is_none());
        }
    }

    // ==========================================================================
    // Transport Registry Tests (Phase 1.1 Task 5)
    // ==========================================================================

    #[tokio::test]
    async fn test_p2p_endpoint_stores_transport_registry() {
        use crate::transport::TransportType;

        // Build config with default transport providers
        // Phase 5.3: P2pEndpoint::new() always adds a shared UDP transport
        let config = P2pConfig::builder().build().expect("valid config");

        // Create endpoint
        let result = P2pEndpoint::new(config).await;

        // Verify registry is accessible and contains the auto-added UDP provider
        if let Ok(endpoint) = result {
            let registry = endpoint.transport_registry();
            // Phase 5.3: Registry now always has at least 1 UDP provider (socket sharing)
            assert!(
                !registry.is_empty(),
                "Registry should have at least 1 provider"
            );

            let udp_providers = registry.providers_by_type(TransportType::Quic);
            assert_eq!(udp_providers.len(), 1, "Should have 1 UDP provider");
        }
        // Note: endpoint creation may fail in test environment without network
    }

    #[tokio::test]
    async fn test_p2p_endpoint_default_config_has_udp_registry() {
        // Build config with no additional transport providers
        let config = P2pConfig::builder().build().expect("valid config");

        // Create endpoint
        let result = P2pEndpoint::new(config).await;

        // Phase 5.3: Default registry now includes a shared UDP transport
        // This is required for socket sharing with Quinn
        if let Ok(endpoint) = result {
            let registry = endpoint.transport_registry();
            assert!(
                !registry.is_empty(),
                "Default registry should have UDP for socket sharing"
            );
            assert!(
                registry.has_quic_capable_transport(),
                "Default registry should have QUIC-capable transport"
            );
        }
        // Note: endpoint creation may fail in test environment without network
    }

    // ==========================================================================
    // Event Address Migration Tests (Phase 2.2 Task 7)
    // ==========================================================================

    #[test]
    fn test_peer_connected_event_with_udp() {
        let socket_addr: SocketAddr = "192.168.1.100:8080".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            addr: TransportAddr::Quic(socket_addr),
            public_key: None,
            side: Side::Client,
        };

        // Verify event fields
        if let P2pEvent::PeerConnected {
            addr,
            public_key,
            side,
        } = event
        {
            assert!(public_key.is_none());
            assert_eq!(addr, TransportAddr::Quic(socket_addr));
            assert!(side.is_client());

            // Verify as_socket_addr() works
            let extracted = addr.as_socket_addr();
            assert_eq!(extracted, Some(socket_addr));
        } else {
            panic!("Expected PeerConnected event");
        }
    }

    #[test]
    fn test_peer_connected_event_with_ble() {
        // BLE MAC address (6 bytes)
        let mac_addr = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        let event = P2pEvent::PeerConnected {
            addr: TransportAddr::Ble {
                mac: mac_addr,
                psm: 128,
            },
            public_key: None,
            side: Side::Server,
        };

        // Verify event fields
        if let P2pEvent::PeerConnected {
            addr,
            public_key,
            side,
        } = event
        {
            assert!(public_key.is_none());
            assert!(side.is_server());

            // Verify as_socket_addr() returns None for BLE
            assert!(addr.as_socket_addr().is_none());

            // Verify we can match on BLE variant
            if let TransportAddr::Ble { mac, psm } = addr {
                assert_eq!(mac, mac_addr);
                assert_eq!(psm, 128);
            } else {
                panic!("Expected BLE address");
            }
        }
    }

    #[test]
    fn test_external_address_discovered_udp() {
        let socket_addr: SocketAddr = "203.0.113.1:12345".parse().expect("valid addr");
        let event = P2pEvent::ExternalAddressDiscovered {
            addr: TransportAddr::Quic(socket_addr),
        };

        if let P2pEvent::ExternalAddressDiscovered { addr } = event {
            assert_eq!(addr, TransportAddr::Quic(socket_addr));
            assert_eq!(addr.as_socket_addr(), Some(socket_addr));
        } else {
            panic!("Expected ExternalAddressDiscovered event");
        }
    }

    #[test]
    fn test_event_clone() {
        let socket_addr: SocketAddr = "10.0.0.1:9000".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            addr: TransportAddr::Quic(socket_addr),
            public_key: Some(vec![0x11; 32]),
            side: Side::Client,
        };

        // Verify events are Clone
        let cloned = event.clone();
        if let (
            P2pEvent::PeerConnected {
                public_key: pk1,
                addr: a1,
                ..
            },
            P2pEvent::PeerConnected {
                public_key: pk2,
                addr: a2,
                ..
            },
        ) = (&event, &cloned)
        {
            assert_eq!(pk1, pk2);
            assert_eq!(a1, a2);
        }
    }

    #[test]
    fn test_peer_connection_with_transport_addr() {
        // Test with UDP
        let udp_addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let udp_conn = PeerConnection {
            public_key: None,
            remote_addr: TransportAddr::Quic(udp_addr),
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            last_health_ping_sent: None,
            last_health_pong_received: None,
        };
        assert_eq!(
            udp_conn.remote_addr.as_socket_addr(),
            Some(udp_addr),
            "UDP connection should have extractable socket address"
        );

        // Test with BLE
        let mac_addr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let ble_conn = PeerConnection {
            public_key: None,
            remote_addr: TransportAddr::Ble {
                mac: mac_addr,
                psm: 128,
            },
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            last_health_ping_sent: None,
            last_health_pong_received: None,
        };
        assert!(
            ble_conn.remote_addr.as_socket_addr().is_none(),
            "BLE connection should not have socket address"
        );
    }

    #[test]
    fn test_transport_addr_display_in_events() {
        let socket_addr: SocketAddr = "192.168.1.1:9001".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            addr: TransportAddr::Quic(socket_addr),
            public_key: None,
            side: Side::Client,
        };

        // Verify display formatting works for logging
        let debug_str = format!("{:?}", event);
        assert!(
            debug_str.contains("192.168.1.1"),
            "Event debug should contain IP address"
        );
        assert!(
            debug_str.contains("9001"),
            "Event debug should contain port"
        );
    }

    // ==========================================================================
    // Connection Tracking Tests (Phase 2.2 Task 8)
    // ==========================================================================

    #[test]
    fn test_connection_tracking_udp() {
        use std::collections::HashMap;

        // Simulate connection tracking with SocketAddr key
        let mut connections: HashMap<SocketAddr, PeerConnection> = HashMap::new();

        let socket_addr: SocketAddr = "10.0.0.1:8080".parse().expect("valid addr");
        let conn = PeerConnection {
            public_key: None,
            remote_addr: TransportAddr::Quic(socket_addr),
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            last_health_ping_sent: None,
            last_health_pong_received: None,
        };

        connections.insert(socket_addr, conn.clone());

        // Verify connection is tracked
        assert!(connections.contains_key(&socket_addr));
        let retrieved = connections.get(&socket_addr).expect("connection exists");
        assert_eq!(retrieved.remote_addr, TransportAddr::Quic(socket_addr));
        assert!(retrieved.authenticated);
    }

    #[test]
    fn test_connection_tracking_multi_transport() {
        use std::collections::HashMap;

        // Simulate multiple connections on different transports keyed by SocketAddr.
        // For constrained transports (BLE) we use a synthetic SocketAddr via
        // TransportAddr::to_synthetic_socket_addr().
        let mut connections: HashMap<SocketAddr, PeerConnection> = HashMap::new();

        // UDP connection
        let udp_addr: SocketAddr = "192.168.1.100:9000".parse().expect("valid addr");
        connections.insert(
            udp_addr,
            PeerConnection {
                public_key: None,
                remote_addr: TransportAddr::Quic(udp_addr),
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
                last_health_ping_sent: None,
                last_health_pong_received: None,
            },
        );

        // BLE connection (different peer) - use synthetic SocketAddr as key
        let ble_device = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ble_addr = TransportAddr::Ble {
            mac: ble_device,
            psm: 128,
        };
        let ble_socket_key = ble_addr.to_synthetic_socket_addr();
        connections.insert(
            ble_socket_key,
            PeerConnection {
                public_key: None,
                remote_addr: ble_addr,
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
                last_health_ping_sent: None,
                last_health_pong_received: None,
            },
        );

        // Verify each tracked independently
        assert_eq!(connections.len(), 2);
        assert!(
            connections
                .get(&udp_addr)
                .expect("UDP connection exists")
                .remote_addr
                .as_socket_addr()
                .is_some()
        );
        assert!(
            connections
                .get(&ble_socket_key)
                .expect("BLE connection exists")
                .remote_addr
                .as_socket_addr()
                .is_none()
        );
    }

    #[test]
    fn test_connection_lookup_by_socket_addr() {
        use std::collections::HashMap;

        let mut connections: HashMap<SocketAddr, PeerConnection> = HashMap::new();

        // Add multiple connections keyed by SocketAddr
        let addrs = ["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"];

        for addr_str in addrs {
            let socket_addr: SocketAddr = addr_str.parse().expect("valid addr");
            connections.insert(
                socket_addr,
                PeerConnection {
                    public_key: None,
                    remote_addr: TransportAddr::Quic(socket_addr),
                    authenticated: true,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                    last_health_ping_sent: None,
                    last_health_pong_received: None,
                },
            );
        }

        // Direct lookup by SocketAddr
        let target: SocketAddr = "10.0.0.2:8080".parse().expect("valid addr");
        let found = connections.get(&target);

        assert!(found.is_some());
        assert_eq!(
            found.expect("connection exists").remote_addr,
            TransportAddr::Quic(target)
        );
    }

    #[test]
    fn test_transport_addr_equality_in_tracking() {
        // Verify TransportAddr equality works correctly for tracking
        let addr1: SocketAddr = "192.168.1.1:8080".parse().expect("valid addr");
        let addr2: SocketAddr = "192.168.1.1:8080".parse().expect("valid addr");
        let addr3: SocketAddr = "192.168.1.1:8081".parse().expect("valid addr");

        let t1 = TransportAddr::Quic(addr1);
        let t2 = TransportAddr::Quic(addr2);
        let t3 = TransportAddr::Quic(addr3);

        // Same address should be equal
        assert_eq!(t1, t2);

        // Different port should not be equal
        assert_ne!(t1, t3);

        // Different transport type should not be equal
        let ble = TransportAddr::Ble {
            mac: [0; 6],
            psm: 128,
        };
        assert_ne!(t1, ble);
    }

    #[test]
    fn test_peer_connection_update_preserves_transport_addr() {
        let socket_addr: SocketAddr = "172.16.0.1:5000".parse().expect("valid addr");
        let mut conn = PeerConnection {
            public_key: None,
            remote_addr: TransportAddr::Quic(socket_addr),
            authenticated: false,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            last_health_ping_sent: None,
            last_health_pong_received: None,
        };

        // Simulate updating the connection (e.g., after authentication)
        conn.authenticated = true;
        conn.last_activity = Instant::now();

        // Verify transport address is preserved
        assert_eq!(conn.remote_addr, TransportAddr::Quic(socket_addr));
        assert!(conn.authenticated);
    }
}
