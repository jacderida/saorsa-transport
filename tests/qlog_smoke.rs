// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Smoke test that the `__qlog` feature wires `QlogStreamer` end-to-end:
//! `set_qlog` writes a JSON-SEQ header, and at least one
//! `RecoveryMetricsUpdated` event is streamed during a small bulk transfer.
//!
//! Run with: `cargo test --features __qlog --test qlog_smoke`

#![cfg(feature = "__qlog")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use saorsa_transport::{
    ClientConfig, Endpoint, EndpointConfig, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    high_level::default_runtime,
};

const ALPN: &[u8] = b"saorsa-qlog-smoke";
const TRANSFER_BYTES: usize = 1024 * 1024;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Server-side recv buffer per `read()` call. Smaller than the transfer so the
/// driver loop fires many recv events and gives the qlog stream multiple
/// chances to emit metric updates.
const RECV_BUF_SIZE: usize = 64 * 1024;

/// Fill byte for the synthetic payload — any non-zero value works.
const FILL_BYTE: u8 = 0xAB;

/// Time we let the driver loop drain after the connection is dropped, so any
/// final qlog events make it into the captured buffer before we read it.
const POST_CLOSE_DRAIN: Duration = Duration::from_millis(200);

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// `Write` adapter that fans bytes into an `Arc<Mutex<Vec<u8>>>` so the test
/// can inspect the qlog stream after the connection is dropped.
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl io::Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self
            .0
            .lock()
            .map_err(|_| io::Error::other("qlog buffer poisoned"))?;
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn build_pair() -> (Endpoint, SocketAddr, Endpoint) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der: rustls::pki_types::CertificateDer<'static> = cert.cert.into();
    let key_der: rustls::pki_types::PrivateKeyDer<'static> =
        rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));

    let server_socket =
        std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let runtime = default_runtime().expect("default_runtime");
    let server = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        server_socket,
        runtime.clone(),
    )
    .unwrap();

    let client_socket =
        std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let mut client =
        Endpoint::new(EndpointConfig::default(), None, client_socket, runtime).unwrap();

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client.set_default_client_config(client_config);

    (server, server_addr, client)
}

#[tokio::test]
async fn qlog_streams_header_and_metrics_event() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let (server, server_addr, client) = build_pair();

    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let mut recv = connection.accept_uni().await.unwrap();
        let mut buf = vec![0u8; RECV_BUF_SIZE];
        let mut total = 0usize;
        while let Some(n) = recv.read(&mut buf).await.unwrap() {
            total += n;
        }
        total
    });

    let mut connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    connection.set_qlog(
        Box::new(SharedBuffer(captured.clone())),
        Some("qlog-smoke".to_string()),
        Some("smoke test for QlogStreamer wiring".to_string()),
    );

    let mut send = connection.open_uni().await.unwrap();
    send.write_all(&vec![FILL_BYTE; TRANSFER_BYTES])
        .await
        .unwrap();
    send.finish().unwrap();

    let received = tokio::time::timeout(SHUTDOWN_TIMEOUT, server_task)
        .await
        .expect("server task did not finish within timeout")
        .expect("server task panicked");
    assert_eq!(
        received, TRANSFER_BYTES,
        "server received truncated payload"
    );

    drop(connection);
    tokio::time::sleep(POST_CLOSE_DRAIN).await;

    let bytes = captured.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&bytes);

    assert!(
        text.contains("\"qlog_format\":\"JSON-SEQ\""),
        "qlog header missing JSON-SEQ marker; first 256 bytes: {:?}",
        &text.chars().take(256).collect::<String>(),
    );
    assert!(
        text.contains("\"qlog_version\":\"0.3\""),
        "qlog header missing version field; first 256 bytes: {:?}",
        &text.chars().take(256).collect::<String>(),
    );
    assert!(
        text.contains("metrics_updated") || text.contains("MetricsUpdated"),
        "expected at least one MetricsUpdated event in qlog stream; got {} bytes",
        bytes.len(),
    );
}
