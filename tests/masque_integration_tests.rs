// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! MASQUE CONNECT-UDP Bind Integration Tests
//!
//! Comprehensive end-to-end tests for the MASQUE relay implementation.
//! Tests cover:
//! - Relay server lifecycle
//! - Client connection and registration
//! - Context compression flow
//! - Datagram forwarding
//! - NAT traversal API integration

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;

use bytes::Bytes;
use saorsa_transport::VarInt;
use saorsa_transport::masque::{
    Capsule,
    // Datagram types
    CompressedDatagram,
    // Capsule types
    CompressionAck,
    CompressionAssign,
    // Connect types
    ConnectUdpRequest,
    ConnectUdpResponse,
    // Context types
    ContextManager,
    // Client types
    MasqueRelayClient,
    // Server types
    MasqueRelayConfig,
    MasqueRelayServer,
    RelayClientConfig,
    RelayConnectionState,
    // Integration types
    RelayManager,
    RelayManagerConfig,
    // Session types
    RelaySession,
    RelaySessionConfig,
    RelaySessionState,
};

/// Test address helper
fn test_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), port)
}

/// Relay address helper
fn relay_addr(id: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, id)), 9000)
}

// ============================================================================
// Relay Server Tests
// ============================================================================

#[tokio::test]
async fn test_relay_server_handles_connect_request() {
    let config = MasqueRelayConfig::default();
    let server = MasqueRelayServer::new(config, relay_addr(1));

    let client_addr = test_addr(12345);
    let request = ConnectUdpRequest::bind_any();

    let response = server
        .handle_connect_request(&request, client_addr)
        .await
        .unwrap();

    assert!(response.is_success());
    assert_eq!(server.stats().active_sessions.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn test_relay_server_session_limit() {
    let config = MasqueRelayConfig {
        max_sessions: 2,
        ..Default::default()
    };
    let server = MasqueRelayServer::new(config, relay_addr(1));

    // Fill up sessions
    for i in 0..2u16 {
        let client = test_addr(12345 + i);
        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, client)
            .await
            .unwrap();
        assert!(response.is_success());
    }

    // Third should get error response (not Err)
    let extra_client = test_addr(12347);
    let request = ConnectUdpRequest::bind_any();
    let response = server
        .handle_connect_request(&request, extra_client)
        .await
        .unwrap();
    assert!(!response.is_success());
}

// ============================================================================
// Relay Client Tests
// ============================================================================

#[tokio::test]
async fn test_relay_client_lifecycle() {
    let config = RelayClientConfig::default();
    let client = MasqueRelayClient::new(relay_addr(1), config);

    // Initial state
    assert!(matches!(
        client.state().await,
        RelayConnectionState::Disconnected
    ));

    // Handle success response
    let response = ConnectUdpResponse::success(Some(test_addr(50000)));
    client.handle_connect_response(response).await.unwrap();

    // Should be connected with public address
    assert!(matches!(
        client.state().await,
        RelayConnectionState::Connected
    ));
    assert!(client.public_address().await.is_some());
}

#[tokio::test]
async fn test_relay_client_context_registration() {
    let config = RelayClientConfig::default();
    let client = MasqueRelayClient::new(relay_addr(1), config);

    // Connect first
    let response = ConnectUdpResponse::success(Some(test_addr(50000)));
    client.handle_connect_response(response).await.unwrap();

    // Get or create context for a target
    let target = test_addr(8080);
    let (context_id, capsule) = client.get_or_create_context(target).await.unwrap();

    // First time should get a COMPRESSION_ASSIGN capsule
    assert!(capsule.is_some());
    match capsule.unwrap() {
        Capsule::CompressionAssign(assign) => {
            assert!(assign.context_id.into_inner() >= 2); // Client uses even IDs >= 2
            assert_eq!(assign.context_id, context_id);
        }
        _ => panic!("Expected CompressionAssign capsule"),
    }
}

#[tokio::test]
async fn test_relay_client_ack_handling() {
    let config = RelayClientConfig::default();
    let client = MasqueRelayClient::new(relay_addr(1), config);

    // Connect
    let response = ConnectUdpResponse::success(Some(test_addr(50000)));
    client.handle_connect_response(response).await.unwrap();

    // Get or create context
    let target = test_addr(8080);
    let (context_id, capsule) = client.get_or_create_context(target).await.unwrap();
    assert!(capsule.is_some());

    // Handle ACK
    let ack = CompressionAck::new(context_id);
    let result = client.handle_capsule(Capsule::CompressionAck(ack)).await;
    assert!(result.is_ok());

    // Check stats
    let stats = client.stats();
    assert_eq!(stats.contexts_registered.load(Ordering::Relaxed), 1);
}

// ============================================================================
// Context Manager Tests
// ============================================================================

#[tokio::test]
async fn test_context_manager_bidirectional() {
    // Client-side manager (even IDs)
    let mut client_mgr = ContextManager::new(true);

    // Server-side manager (odd IDs)
    let mut server_mgr = ContextManager::new(false);

    // Client allocates context
    let client_ctx = client_mgr.allocate_local().unwrap();
    assert_eq!(client_ctx.into_inner() % 2, 0); // Even

    // Server allocates context
    let server_ctx = server_mgr.allocate_local().unwrap();
    assert_eq!(server_ctx.into_inner() % 2, 1); // Odd

    // Client registers target
    let target = test_addr(8080);
    client_mgr.register_compressed(client_ctx, target).unwrap();

    // Server registers remote context
    server_mgr
        .register_remote(client_ctx, Some(target))
        .unwrap();

    // Verify both can look up target
    let client_target = client_mgr.get_target(client_ctx);
    let server_target = server_mgr.get_target(client_ctx);

    assert_eq!(client_target, Some(target));
    assert_eq!(server_target, Some(target));
}

// ============================================================================
// Relay Manager Integration Tests
// ============================================================================

#[tokio::test]
async fn test_relay_manager_multi_relay() {
    let config = RelayManagerConfig {
        max_relays: 3,
        ..Default::default()
    };
    let manager = RelayManager::new(config);

    // Add multiple relays
    manager.add_relay_node(relay_addr(1)).await;
    manager.add_relay_node(relay_addr(2)).await;
    manager.add_relay_node(relay_addr(3)).await;

    // All should be available
    let available = manager.available_relays().await;
    assert_eq!(available.len(), 3);

    // Handle success for first relay
    let response = ConnectUdpResponse::success(Some(test_addr(50000)));
    manager
        .handle_connect_response(relay_addr(1), response)
        .await
        .unwrap();

    // Stats should reflect connection
    let stats = manager.stats();
    assert_eq!(stats.successful_connections.load(Ordering::Relaxed), 1);
    assert_eq!(stats.active_count(), 1);
}

#[tokio::test]
async fn test_relay_manager_error_tracking() {
    let config = RelayManagerConfig::default();
    let manager = RelayManager::new(config);

    manager.add_relay_node(relay_addr(1)).await;

    // Handle error response
    let response = ConnectUdpResponse::error(503, "Server busy");
    let result = manager
        .handle_connect_response(relay_addr(1), response)
        .await;
    assert!(result.is_err());

    // Stats should reflect failure
    let stats = manager.stats();
    assert_eq!(stats.failed_connections.load(Ordering::Relaxed), 1);
    assert_eq!(stats.active_count(), 0);
}

// ============================================================================
// Session Tests
// ============================================================================

#[tokio::test]
async fn test_relay_session_compression_flow() {
    let config = RelaySessionConfig::default();
    let client = test_addr(12345);
    let mut session = RelaySession::new(1, config, client);

    // Activate session
    session.activate().unwrap();
    assert!(matches!(session.state(), RelaySessionState::Active));

    // Handle COMPRESSION_ASSIGN from client
    let assign = CompressionAssign::compressed_v4(
        VarInt::from_u32(2),
        Ipv4Addr::new(192, 168, 1, 100),
        8080,
    );

    let response = session
        .handle_capsule(Capsule::CompressionAssign(assign))
        .unwrap();

    // Should get ACK back
    assert!(matches!(response, Some(Capsule::CompressionAck(_))));

    // Context should be registered
    let stats = session.stats();
    assert_eq!(stats.contexts_registered.load(Ordering::Relaxed), 1);
}

// ============================================================================
// Datagram Tests
// ============================================================================

#[tokio::test]
async fn test_compressed_datagram_roundtrip() {
    let context_id = VarInt::from_u32(2);
    let payload = Bytes::from("Hello, MASQUE!");

    let datagram = CompressedDatagram::new(context_id, payload.clone());
    let encoded = datagram.encode();

    let decoded = CompressedDatagram::decode(&mut encoded.clone()).unwrap();
    assert_eq!(decoded.context_id, context_id);
    assert_eq!(decoded.payload, payload);
}

// ============================================================================
// End-to-End Scenario Tests
// ============================================================================

#[tokio::test]
async fn test_e2e_relay_scenario() {
    // Setup relay server
    let server_config = MasqueRelayConfig::default();
    let server = MasqueRelayServer::new(server_config, relay_addr(1));

    // Setup client
    let client_config = RelayClientConfig::default();
    let client = MasqueRelayClient::new(relay_addr(1), client_config);

    // Client connects to relay
    let request = ConnectUdpRequest::bind_any();
    let response = server
        .handle_connect_request(&request, test_addr(12345))
        .await
        .unwrap();

    // Client receives response
    client.handle_connect_response(response).await.unwrap();
    assert!(matches!(
        client.state().await,
        RelayConnectionState::Connected
    ));

    // Client wants to reach a target
    let target = test_addr(8080);
    let (context_id, capsule) = client.get_or_create_context(target).await.unwrap();

    // Verify capsule is valid
    assert!(capsule.is_some());
    match capsule.unwrap() {
        Capsule::CompressionAssign(assign) => {
            assert_eq!(assign.context_id, context_id);
            assert!(assign.context_id.into_inner() >= 2);
        }
        _ => panic!("Expected CompressionAssign"),
    }

    // Cleanup
    client.close().await;
}

// ============================================================================
// Performance Tests
// ============================================================================

#[tokio::test]
async fn test_high_session_count() {
    let config = MasqueRelayConfig {
        max_sessions: 100,
        ..Default::default()
    };
    let server = MasqueRelayServer::new(config, relay_addr(1));

    // Create many sessions
    for i in 0..50u16 {
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8)), 12345 + i);
        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, client)
            .await
            .unwrap();
        assert!(response.is_success());
    }

    assert_eq!(server.stats().active_sessions.load(Ordering::Relaxed), 50);
}

#[tokio::test]
async fn test_context_allocation_stress() {
    let mut manager = ContextManager::new(true);

    // Allocate many contexts with unique targets
    for i in 0..100u16 {
        let ctx = manager.allocate_local().unwrap();
        // Each context needs a unique target address
        let target = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, (i / 250) as u8 + 1)),
            8000 + i,
        );
        manager.register_compressed(ctx, target).unwrap();
        manager.handle_ack(ctx).unwrap();
    }

    // Close some
    for i in 0..50u32 {
        let ctx = VarInt::from_u32((i + 1) * 2); // Even IDs for client
        let _ = manager.close(ctx);
    }

    // Should still work
    let new_ctx = manager.allocate_local().unwrap();
    assert!(new_ctx.into_inner() >= 2);
}
