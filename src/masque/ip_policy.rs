// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! IP-based policy for MASQUE relay selection and acceptance.
//!
//! Enforces two rules on top of the standard relay client/server flows:
//!
//! 1. **Same-IP relay rejection (client side).** A node must never establish a
//!    relay through another node that shares one of its own known IPs. Such a
//!    "relay" would either loop back to the node itself or bounce through a
//!    co-located host that provides no network-diversity benefit.
//!
//! 2. **Upstream-IP relay rejection (server side).** A node must never accept
//!    relaying for a peer whose IP matches one of the relays the node is
//!    currently being relayed through. Otherwise traffic could loop through the
//!    same upstream, turning the node into a one-hop amplifier for its own
//!    upstream relay.
//!
//! Both rules are bypassed when [`IpPolicy::set_local_testnet`] is set to
//! `true`, because local/integration testnets routinely run many nodes on a
//! single host and rely on `127.0.0.1`/loopback relays.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::RwLock;

/// Why an IP-policy check denied a relay operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDenial {
    /// The prospective relay's IP matches one of this node's own IPs.
    SameIpRelay {
        /// The relay IP that collided with a local IP.
        relay_ip: IpAddr,
    },
    /// The prospective relay client's IP matches one of our upstream relays.
    UpstreamIpClient {
        /// The client IP that is currently acting as one of our upstreams.
        client_ip: IpAddr,
    },
}

impl fmt::Display for PolicyDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameIpRelay { relay_ip } => write!(
                f,
                "relay at {} shares a local IP; refusing to establish (same-IP policy)",
                relay_ip
            ),
            Self::UpstreamIpClient { client_ip } => write!(
                f,
                "client at {} is one of our upstream relays; refusing to accept (upstream-IP policy)",
                client_ip
            ),
        }
    }
}

impl std::error::Error for PolicyDenial {}

/// Shared IP-diversity policy between the relay client and relay server halves
/// of a single node.
///
/// Cloning is cheap: wrap in [`Arc`] at the top level (see
/// [`IpPolicy::shared`]) and hand the same handle to both the [`super::RelayManager`]
/// and the [`super::MasqueRelayServer`] so they observe a consistent view of
/// local IPs and current upstream relays.
#[derive(Debug)]
pub struct IpPolicy {
    local_addresses: RwLock<HashSet<IpAddr>>,
    upstream_relay_ips: RwLock<HashSet<IpAddr>>,
    local_testnet: AtomicBool,
}

impl Default for IpPolicy {
    fn default() -> Self {
        Self {
            local_addresses: RwLock::new(HashSet::new()),
            upstream_relay_ips: RwLock::new(HashSet::new()),
            local_testnet: AtomicBool::new(false),
        }
    }
}

impl IpPolicy {
    /// Create an empty policy enforcing both rules (not in local-testnet mode).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an `Arc`-wrapped policy for sharing between client and server.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Whether local-testnet mode is enabled. When `true`, all policy checks
    /// pass unconditionally.
    pub fn is_local_testnet(&self) -> bool {
        self.local_testnet.load(Ordering::Acquire)
    }

    /// Enable or disable local-testnet mode. See the module docs for why this
    /// bypass exists.
    pub fn set_local_testnet(&self, enabled: bool) {
        self.local_testnet.store(enabled, Ordering::Release);
    }

    /// Register an IP address that belongs to this node (bind address, NAT-
    /// reflected public address, secondary dual-stack address, etc.).
    ///
    /// Wildcard (`0.0.0.0` / `::`) addresses are ignored: they do not identify
    /// any particular host and would spuriously match every peer.
    pub fn add_local_address(&self, ip: IpAddr) {
        if ip.is_unspecified() {
            return;
        }
        self.local_addresses.write().insert(ip);
    }

    /// Remove a previously registered local IP.
    pub fn remove_local_address(&self, ip: IpAddr) {
        self.local_addresses.write().remove(&ip);
    }

    /// Snapshot of the currently known local IPs (primarily for diagnostics).
    pub fn local_addresses(&self) -> Vec<IpAddr> {
        self.local_addresses.read().iter().copied().collect()
    }

    /// Record that this node has established a relay session through `relay`.
    /// Subsequent calls to [`IpPolicy::check_accept_client`] will reject any
    /// client connecting from the same IP.
    pub fn register_upstream_relay(&self, relay: SocketAddr) {
        if relay.ip().is_unspecified() {
            return;
        }
        self.upstream_relay_ips.write().insert(relay.ip());
    }

    /// Stop tracking `relay` as an upstream — call this when the relay session
    /// has ended. If multiple upstream relays share the same IP (unusual but
    /// possible over different ports) this removes the IP entirely; callers
    /// should register after removal if any remain.
    pub fn unregister_upstream_relay(&self, relay: SocketAddr) {
        self.upstream_relay_ips.write().remove(&relay.ip());
    }

    /// Snapshot of the currently known upstream relay IPs.
    pub fn upstream_relay_ips(&self) -> Vec<IpAddr> {
        self.upstream_relay_ips.read().iter().copied().collect()
    }

    /// Rule 1: can we establish a relay to `relay`? Returns `Err` if the
    /// relay's IP matches a local IP and local-testnet mode is off.
    pub fn check_establish_relay(&self, relay: SocketAddr) -> Result<(), PolicyDenial> {
        if self.is_local_testnet() {
            return Ok(());
        }
        if self.local_addresses.read().contains(&relay.ip()) {
            return Err(PolicyDenial::SameIpRelay {
                relay_ip: relay.ip(),
            });
        }
        Ok(())
    }

    /// Rule 2: can we accept a relay session from `client`? Returns `Err` if
    /// the client's IP matches one of our current upstream relays and local-
    /// testnet mode is off.
    pub fn check_accept_client(&self, client: SocketAddr) -> Result<(), PolicyDenial> {
        if self.is_local_testnet() {
            return Ok(());
        }
        if self.upstream_relay_ips.read().contains(&client.ip()) {
            return Err(PolicyDenial::UpstreamIpClient {
                client_ip: client.ip(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port)
    }

    #[test]
    fn same_ip_relay_is_rejected() {
        let policy = IpPolicy::new();
        policy.add_local_address(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));

        let relay = v4([203, 0, 113, 5], 9000);
        assert_eq!(
            policy.check_establish_relay(relay),
            Err(PolicyDenial::SameIpRelay {
                relay_ip: relay.ip()
            })
        );
    }

    #[test]
    fn different_ip_relay_is_allowed() {
        let policy = IpPolicy::new();
        policy.add_local_address(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));

        assert!(
            policy
                .check_establish_relay(v4([198, 51, 100, 1], 9000))
                .is_ok()
        );
    }

    #[test]
    fn local_testnet_bypasses_same_ip_rejection() {
        let policy = IpPolicy::new();
        policy.add_local_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        policy.set_local_testnet(true);

        assert!(
            policy
                .check_establish_relay(v4([127, 0, 0, 1], 9000))
                .is_ok()
        );
    }

    #[test]
    fn upstream_ip_client_is_rejected() {
        let policy = IpPolicy::new();
        policy.register_upstream_relay(v4([198, 51, 100, 42], 9000));

        let client = v4([198, 51, 100, 42], 55555);
        assert_eq!(
            policy.check_accept_client(client),
            Err(PolicyDenial::UpstreamIpClient {
                client_ip: client.ip()
            })
        );
    }

    #[test]
    fn non_upstream_client_is_allowed() {
        let policy = IpPolicy::new();
        policy.register_upstream_relay(v4([198, 51, 100, 42], 9000));

        assert!(
            policy
                .check_accept_client(v4([192, 0, 2, 10], 55555))
                .is_ok()
        );
    }

    #[test]
    fn unregister_upstream_removes_block() {
        let policy = IpPolicy::new();
        let relay = v4([198, 51, 100, 42], 9000);
        policy.register_upstream_relay(relay);
        policy.unregister_upstream_relay(relay);

        assert!(
            policy
                .check_accept_client(v4([198, 51, 100, 42], 55555))
                .is_ok()
        );
    }

    #[test]
    fn local_testnet_bypasses_upstream_rejection() {
        let policy = IpPolicy::new();
        policy.register_upstream_relay(v4([127, 0, 0, 1], 9000));
        policy.set_local_testnet(true);

        assert!(
            policy
                .check_accept_client(v4([127, 0, 0, 1], 55555))
                .is_ok()
        );
    }

    #[test]
    fn wildcard_addresses_are_ignored() {
        let policy = IpPolicy::new();
        policy.add_local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        policy.add_local_address(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        policy.register_upstream_relay(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000));

        assert!(policy.local_addresses().is_empty());
        assert!(policy.upstream_relay_ips().is_empty());
    }

    #[test]
    fn ipv6_same_ip_relay_is_rejected() {
        let policy = IpPolicy::new();
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        policy.add_local_address(ipv6);

        let relay = SocketAddr::new(ipv6, 9000);
        assert!(matches!(
            policy.check_establish_relay(relay),
            Err(PolicyDenial::SameIpRelay { .. })
        ));
    }
}
