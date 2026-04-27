//! mTLS peer streams: listener side and dialer side.
//!
//! Both produce a [`PeerStream`] that carries the underlying `TlsStream`
//! along with the peer's claimed `node_id` (extracted from the cert SAN
//! after the handshake completes). The handshake layer further validates
//! that this matches the `node_id` advertised in `PeerHello`.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::tls::cert_node_id;

/// One mTLS-protected peer connection.
pub struct PeerStream<S> {
    /// `node_id` from the peer cert's SAN (or Subject CN as fallback).
    pub peer_node_id: String,
    /// Remote socket address.
    pub remote_addr: SocketAddr,
    /// Underlying TLS stream.
    pub tls: S,
}

impl<S> std::fmt::Debug for PeerStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerStream")
            .field("peer_node_id", &self.peer_node_id)
            .field("remote_addr", &self.remote_addr)
            .finish_non_exhaustive()
    }
}

/// Errors from accepting or dialing a peer.
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("peer cert had no usable Subject CN or SAN")]
    PeerCertNoIdentity,
    #[error("peer presented no client certificate")]
    PeerCertMissing,
    #[error("expected peer node_id `{expected}` but cert advertised `{actual}`")]
    NodeIdMismatch { expected: String, actual: String },
    #[error("invalid server name `{0}`")]
    InvalidServerName(String),
}

/// Listener side: accept one peer, drive the TLS handshake, return a
/// [`PeerStream`] with the peer's claimed `node_id` populated.
pub async fn accept_peer(
    listener: &TcpListener,
    server_config: Arc<ServerConfig>,
) -> Result<PeerStream<tokio_rustls::server::TlsStream<TcpStream>>, PeerError> {
    let (tcp, remote_addr) = listener.accept().await?;
    tcp.set_nodelay(true)?;
    let acceptor = TlsAcceptor::from(server_config);
    let tls = acceptor.accept(tcp).await?;
    let (_io, conn) = tls.get_ref();
    let peer_certs = conn.peer_certificates().ok_or(PeerError::PeerCertMissing)?;
    let leaf = peer_certs.first().ok_or(PeerError::PeerCertMissing)?;
    let peer_node_id = cert_node_id(leaf).ok_or(PeerError::PeerCertNoIdentity)?;
    Ok(PeerStream {
        peer_node_id,
        remote_addr,
        tls,
    })
}

/// Dialer side: connect to `addr`, drive the TLS handshake against
/// `expected_server_name`, and verify the cert SAN matches
/// `expected_node_id` before returning.
pub async fn dial_peer(
    addr: SocketAddr,
    expected_server_name: &str,
    expected_node_id: &str,
    client_config: Arc<ClientConfig>,
) -> Result<PeerStream<tokio_rustls::client::TlsStream<TcpStream>>, PeerError> {
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let connector = TlsConnector::from(client_config);
    let server_name: ServerName<'static> = expected_server_name
        .to_owned()
        .try_into()
        .map_err(|_| PeerError::InvalidServerName(expected_server_name.to_owned()))?;
    let tls = connector.connect(server_name, tcp).await?;

    let (_io, conn) = tls.get_ref();
    let peer_certs = conn.peer_certificates().ok_or(PeerError::PeerCertMissing)?;
    let leaf = peer_certs.first().ok_or(PeerError::PeerCertMissing)?;
    let peer_node_id = cert_node_id(leaf).ok_or(PeerError::PeerCertNoIdentity)?;
    if peer_node_id != expected_node_id {
        return Err(PeerError::NodeIdMismatch {
            expected: expected_node_id.to_owned(),
            actual: peer_node_id,
        });
    }

    Ok(PeerStream {
        peer_node_id,
        remote_addr: addr,
        tls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::test_pki::TestPki;
    use crate::tls::{client_config, server_config};

    async fn accept_then_check(
        listener: TcpListener,
        srv_cfg: Arc<ServerConfig>,
    ) -> Result<String, PeerError> {
        let peer = accept_peer(&listener, srv_cfg).await?;
        Ok(peer.peer_node_id)
    }

    #[tokio::test]
    async fn accept_and_dial_round_trip_with_matching_certs() {
        let pki = TestPki::new();
        let server_node = pki.issue("server-node");
        let client_node = pki.issue("client-node");
        let ca = vec![pki.ca_cert_der.clone()];

        let srv_cfg = Arc::new(
            server_config(ca.clone(), vec![server_node.cert_der], server_node.key_der).unwrap(),
        );
        let cli_cfg =
            Arc::new(client_config(ca, vec![client_node.cert_der], client_node.key_der).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(accept_then_check(listener, srv_cfg));
        let dialed = dial_peer(addr, "server-node", "server-node", cli_cfg)
            .await
            .unwrap();
        assert_eq!(dialed.peer_node_id, "server-node");

        let server_seen = server_task.await.unwrap().unwrap();
        assert_eq!(server_seen, "client-node");
    }

    #[tokio::test]
    async fn dial_rejects_unexpected_node_id() {
        let pki = TestPki::new();
        let server_node = pki.issue("server-node");
        let client_node = pki.issue("client-node");
        let ca = vec![pki.ca_cert_der.clone()];

        let srv_cfg = Arc::new(
            server_config(ca.clone(), vec![server_node.cert_der], server_node.key_der).unwrap(),
        );
        let cli_cfg =
            Arc::new(client_config(ca, vec![client_node.cert_der], client_node.key_der).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            // Just complete the TLS accept; we don't care about the result.
            let _ = accept_peer(&listener, srv_cfg).await;
        });
        let err = dial_peer(addr, "server-node", "wrong-node", cli_cfg)
            .await
            .unwrap_err();
        let _ = server_task.await;
        assert!(
            matches!(
                err,
                PeerError::NodeIdMismatch { ref expected, ref actual }
                if expected == "wrong-node" && actual == "server-node"
            ),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn dial_with_unrelated_ca_fails_handshake() {
        let pki_a = TestPki::new();
        let pki_b = TestPki::new();

        let server_node = pki_a.issue("server-node");
        let client_node = pki_b.issue("client-node");

        let srv_cfg = Arc::new(
            server_config(
                vec![pki_a.ca_cert_der.clone()],
                vec![server_node.cert_der],
                server_node.key_der,
            )
            .unwrap(),
        );
        // Client trusts pki_a's CA but presents a cert signed by pki_b
        // — server rejects the client cert.
        let cli_cfg = Arc::new(
            client_config(
                vec![pki_a.ca_cert_der.clone()],
                vec![client_node.cert_der],
                client_node.key_der,
            )
            .unwrap(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            // Expect the accept to fail because the client cert isn't
            // signed by the configured CA.
            let res = accept_peer(&listener, srv_cfg).await;
            res.is_err()
        });

        let dial_res = dial_peer(addr, "server-node", "server-node", cli_cfg).await;
        let server_failed = server_task.await.unwrap();
        // We require at least the server to reject the unrelated client
        // cert. The client side may or may not see an alert before its
        // local handshake completes — either is acceptable as long as
        // the server rejected the connection.
        assert!(server_failed, "server accept must reject unrelated CA");
        // If the dial somehow appeared to succeed, the very next read
        // would fail anyway because the server has dropped the socket.
        // We don't assert on dial_res.
        let _ = dial_res;
    }
}
