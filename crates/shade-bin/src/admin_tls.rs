//! TLS-enabled admin listener.
//!
//! `serve_admin_tls` runs the accept loop for `admin.listen` when
//! `admin.require_mtls = true`. Each accepted connection:
//!
//! 1. Completes a rustls handshake configured with `WebPkiClientVerifier`
//!    rooted at `admin.client_ca`. Connections without a trusted client
//!    cert are dropped during the handshake.
//! 2. Extracts the verified peer cert's Subject CN — the operator handle.
//! 3. Wraps the admin router in an `Extension(VerifiedActor(handle))`
//!    layer so every request from this connection is tagged with the
//!    cryptographically authenticated actor.
//! 4. Serves HTTP/1.1 over the TLS stream via hyper-util.
//!
//! The plain-TCP `serve` path remains for tests and the M3-style demo
//! (no admin certs on disk). Production deployments must keep
//! `require_mtls = true`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use shade_api::auth::VerifiedActor;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::config::AdminConfig;
use crate::shutdown::ShutdownSignal;

/// Build the rustls `ServerConfig` for the admin listener.
///
/// `client_ca_bundle` is the CA whose signatures on operator client
/// certs will be honored. `cert_chain` + `key` is the server identity.
pub fn build_server_config(
    client_ca_bundle: Vec<CertificateDer<'static>>,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>> {
    let cfg = shade_mesh::admin_server_config(client_ca_bundle, cert_chain, key)
        .map_err(|e| anyhow!("admin TLS config: {e}"))?;
    Ok(Arc::new(cfg))
}

/// Accept loop for the TLS-enabled admin listener.
///
/// Returns when the listener fails to bind, when `accept()` errors
/// fatally, or when `shutdown` fires. On shutdown the accept loop
/// stops accepting new connections immediately and then waits for
/// every spawned per-connection task to finish — same drain semantics
/// as `axum::serve(...).with_graceful_shutdown(...)` for the plain-TCP
/// path. Per-connection errors are logged and the loop continues.
pub async fn serve_admin_tls(
    addr: SocketAddr,
    server_config: Arc<ServerConfig>,
    router: axum::Router,
    shutdown: ShutdownSignal,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(server_config);
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding admin TLS listener on {addr}"))?;
    tracing::info!(%addr, "admin listener bound (mTLS)");

    let mut conns = JoinSet::new();
    let mut shutdown_fut = std::pin::pin!(shutdown.recv());

    loop {
        tokio::select! {
            biased;
            // Shutdown: stop accepting; fall through to drain.
            () = &mut shutdown_fut => {
                tracing::info!(%addr, "admin: shutdown received, draining connections");
                break;
            }
            // Accept a new connection.
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer_addr)) => {
                        let acceptor = acceptor.clone();
                        let router = router.clone();
                        conns.spawn(async move {
                            if let Err(err) =
                                handle_connection(stream, peer_addr, acceptor, router).await
                            {
                                tracing::debug!(%peer_addr, %err, "admin: connection ended with error");
                            }
                        });
                    }
                    Err(err) => {
                        tracing::warn!(%err, "admin: accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            // Reap finished connection tasks while we wait, so the
            // JoinSet doesn't grow unbounded under load.
            Some(_) = conns.join_next() => {}
        }
    }

    // Drain phase: wait for every in-flight connection. The outer
    // `run()` already wraps us in a timeout, so we don't need our own
    // deadline here — if connections hang, the outer abort takes
    // over.
    while let Some(_res) = conns.join_next().await {}
    tracing::info!(%addr, "admin: drained {} connection(s)", 0);
    Ok(())
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    base_router: axum::Router,
) -> Result<()> {
    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(%peer_addr, %err, "admin: TLS handshake failed");
            return Ok(());
        }
    };

    let actor = {
        let (_, conn) = tls_stream.get_ref();
        let cn = conn
            .peer_certificates()
            .and_then(<[CertificateDer<'_>]>::first)
            .and_then(shade_mesh::cert_subject_cn);
        match cn {
            Some(cn) if !cn.is_empty() => cn,
            _ => {
                tracing::warn!(
                    %peer_addr,
                    "admin: client cert has no usable subject CN; closing"
                );
                return Ok(());
            }
        }
    };

    tracing::debug!(%peer_addr, %actor, "admin: TLS handshake ok");

    let svc = base_router.layer(axum::Extension(VerifiedActor(actor)));
    let svc = TowerToHyperService::new(svc);

    Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(tls_stream), svc)
        .await
        .map_err(|err| anyhow!("admin: serving connection: {err}"))?;
    Ok(())
}

/// `true` when the admin TLS material is on disk and we should bring
/// the mTLS listener up. Falls back to the node's mesh cert/key when
/// `admin.server_cert` / `admin.server_key` are unset.
#[must_use]
pub fn admin_tls_present(admin: &AdminConfig, node_cert: &std::path::Path) -> bool {
    admin.client_ca.exists()
        && admin
            .server_cert
            .as_deref()
            .map_or_else(|| node_cert.exists(), std::path::Path::exists)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use axum::routing::get;
    use axum::{Json, Router};
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, SanType,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ClientConfig, RootCertStore};
    use shade_api::auth::ActorClaim;
    use tokio::net::TcpListener;

    /// Self-signed CA + matching server / client certs for tests in this
    /// module. Mirrors the production `init_ca` + `issue_cert` /
    /// `issue_admin_cert` shape but stays in-memory.
    #[allow(clippy::struct_field_names)] // ca_* prefix is descriptive here.
    struct TestPki {
        ca_der: CertificateDer<'static>,
        ca_kp_pem: String,
        ca_rcgen: rcgen::Certificate,
    }

    struct IssuedCert {
        cert_der: CertificateDer<'static>,
        key_pkcs8: Vec<u8>,
    }

    impl IssuedCert {
        fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
            vec![self.cert_der.clone()]
        }
        fn key(&self) -> PrivateKeyDer<'static> {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8.clone()))
        }
    }

    impl TestPki {
        fn new() -> Self {
            let kp = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "Shade Admin Test CA");
            params.distinguished_name = dn;
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
            ];
            let cert = params.self_signed(&kp).unwrap();
            Self {
                ca_der: CertificateDer::from(cert.der().to_vec()),
                ca_kp_pem: kp.serialize_pem(),
                ca_rcgen: cert,
            }
        }

        fn issue_server(&self, dns_name: &str) -> IssuedCert {
            let ca_kp = KeyPair::from_pem(&self.ca_kp_pem).unwrap();
            let kp = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let mut params = CertificateParams::new(vec![dns_name.to_owned()]).unwrap();
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, dns_name);
            params.distinguished_name = dn;
            params.subject_alt_names =
                vec![SanType::DnsName(dns_name.to_owned().try_into().unwrap())];
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            let signed = params.signed_by(&kp, &self.ca_rcgen, &ca_kp).unwrap();
            IssuedCert {
                cert_der: CertificateDer::from(signed.der().to_vec()),
                key_pkcs8: kp.serialize_der(),
            }
        }

        fn issue_admin(&self, handle: &str) -> IssuedCert {
            let ca_kp = KeyPair::from_pem(&self.ca_kp_pem).unwrap();
            let kp = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, handle);
            params.distinguished_name = dn;
            // No SAN — admin certs are not server identities.
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let signed = params.signed_by(&kp, &self.ca_rcgen, &ca_kp).unwrap();
            IssuedCert {
                cert_der: CertificateDer::from(signed.der().to_vec()),
                key_pkcs8: kp.serialize_der(),
            }
        }
    }

    fn install_crypto_provider_once() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn echo_router() -> Router {
        Router::new().route(
            "/whoami",
            get(|claim: ActorClaim| async move { Json(serde_json::json!({ "actor": claim.0 })) }),
        )
    }

    fn rustls_client(roots: &[CertificateDer<'static>], cert: Option<&IssuedCert>) -> ClientConfig {
        let mut store = RootCertStore::empty();
        for c in roots {
            store.add(c.clone()).unwrap();
        }
        let builder = ClientConfig::builder().with_root_certificates(store);
        match cert {
            Some(c) => builder
                .with_client_auth_cert(c.cert_chain(), c.key())
                .unwrap(),
            None => builder.with_no_client_auth(),
        }
    }

    /// Spawn the admin TLS accept loop on 127.0.0.1:0 and return the
    /// bound port plus a `JoinHandle` to abort when the test ends.
    async fn spawn_listener(
        ca: &TestPki,
        server: &IssuedCert,
        router: Router,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let server_config =
            build_server_config(vec![ca.ca_der.clone()], server.cert_chain(), server.key())
                .unwrap();
        let acceptor = TlsAcceptor::from(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, peer_addr)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let router = router.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, peer_addr, acceptor, router).await;
                });
            }
        });
        (port, handle)
    }

    async fn ureq_get(
        port: u16,
        path: &str,
        client_tls: ClientConfig,
    ) -> std::result::Result<String, Box<ureq::Error>> {
        let url = format!("https://localhost:{port}{path}");
        tokio::task::spawn_blocking(move || {
            let agent = ureq::AgentBuilder::new()
                .tls_config(Arc::new(client_tls))
                .timeout(Duration::from_secs(5))
                .build();
            agent
                .get(&url)
                .call()
                .map(|r| r.into_string().unwrap())
                .map_err(Box::new)
        })
        .await
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn happy_path_actor_is_cert_cn() {
        install_crypto_provider_once();
        let ca = TestPki::new();
        let server = ca.issue_server("localhost");
        let admin = ca.issue_admin("alice");

        let (port, handle) = spawn_listener(&ca, &server, echo_router()).await;

        let client_tls = rustls_client(std::slice::from_ref(&ca.ca_der), Some(&admin));
        let body = ureq_get(port, "/whoami", client_tls).await.unwrap();
        assert!(
            body.contains("\"alice\""),
            "actor should be cert CN, body was: {body}"
        );

        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_client_with_no_cert() {
        install_crypto_provider_once();
        let ca = TestPki::new();
        let server = ca.issue_server("localhost");
        let (port, handle) = spawn_listener(&ca, &server, echo_router()).await;

        let client_tls = rustls_client(std::slice::from_ref(&ca.ca_der), None);
        let err = ureq_get(port, "/whoami", client_tls).await.unwrap_err();
        // Either a transport error or a server-side close — both are
        // valid signals that the handshake refused us.
        match *err {
            ureq::Error::Transport(_) => {}
            ureq::Error::Status(code, _) => panic!("expected handshake failure, got {code}"),
        }

        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_client_cert_from_other_ca() {
        install_crypto_provider_once();
        let server_ca = TestPki::new();
        let server = server_ca.issue_server("localhost");
        let (port, handle) = spawn_listener(&server_ca, &server, echo_router()).await;

        // Client cert chained to a *different* CA than the server trusts.
        let other_ca = TestPki::new();
        let intruder = other_ca.issue_admin("mallory");

        let client_tls = rustls_client(std::slice::from_ref(&server_ca.ca_der), Some(&intruder));
        let err = ureq_get(port, "/whoami", client_tls).await.unwrap_err();
        match *err {
            ureq::Error::Transport(_) => {}
            ureq::Error::Status(code, _) => panic!("expected handshake failure, got {code}"),
        }

        handle.abort();
    }
}
