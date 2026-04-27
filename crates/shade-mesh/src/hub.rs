//! `MeshHub` — listener + dialers + connected-peer registry.
//!
//! One hub per node. Owns:
//!
//! * The mTLS listener task accepting inbound peer connections.
//! * One dialer task per statically-configured peer endpoint, with
//!   exponential-backoff reconnect.
//! * A registry mapping peer `node_id` → outbound `mpsc::Sender<Frame>`
//!   for fan-out broadcasts.
//! * A `peers_up` `Arc<AtomicBool>` that flips `true` while at least
//!   one peer is connected — wired to `/readyz`.
//!
//! `MeshHub::broadcast_upsert` / `broadcast_delete` are the entry
//! points the rest of the daemon calls after a local store mutation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, ServerConfig};
use shade_proto::{Delete, Frame, PeerHello, Upsert, PROTO_VERSION};
use shade_store::Store;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::handshake::{run_handshake, HandshakeError};
use crate::peer::{accept_peer, dial_peer};
use crate::peer_loop::{run_peer, PeerLoopError};

/// Configuration handed to `MeshHub::spawn`.
pub struct MeshHubConfig {
    pub node_id: String,
    pub listen_addr: SocketAddr,
    pub server_config: Arc<ServerConfig>,
    pub client_config: Arc<ClientConfig>,
    pub peers: Vec<MeshPeer>,
    /// Channels we'd advertise in `PeerHello` (informational; mesh sync
    /// itself doesn't filter by channel yet).
    pub channels: Vec<String>,
}

/// One statically-configured peer the dialer will keep connected.
#[derive(Debug, Clone)]
pub struct MeshPeer {
    pub node_id: String,
    pub endpoint: SocketAddr,
}

/// Errors from `MeshHub::spawn`.
#[derive(Debug, thiserror::Error)]
pub enum HubError {
    #[error("binding mesh listener: {0}")]
    Listen(#[source] std::io::Error),
}

/// Handle to a running mesh hub.
pub struct MeshHub {
    inner: Arc<HubInner>,
    listener_task: JoinHandle<()>,
    dialer_tasks: Vec<JoinHandle<()>>,
}

struct HubInner {
    node_id: String,
    channels: Vec<String>,
    store: Arc<Store>,
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
    /// Peer node_id → mpsc sender for outbound frames.
    peers: Mutex<HashMap<String, mpsc::Sender<Frame>>>,
    peers_up: Arc<AtomicBool>,
    peer_count: AtomicUsize,
}

impl MeshHub {
    /// Spawn the listener + every configured dialer. Returns the
    /// handle; drop it (or call `shutdown`) to stop everything.
    pub async fn spawn(store: Arc<Store>, config: MeshHubConfig) -> Result<Self, HubError> {
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(HubError::Listen)?;
        info!(addr = %config.listen_addr, "mesh: listening for peers");
        let inner = Arc::new(HubInner {
            node_id: config.node_id,
            channels: config.channels,
            store,
            server_config: config.server_config,
            client_config: config.client_config,
            peers: Mutex::new(HashMap::new()),
            peers_up: Arc::new(AtomicBool::new(false)),
            peer_count: AtomicUsize::new(0),
        });

        let listener_task = tokio::spawn(run_listener(listener, inner.clone()));
        let mut dialer_tasks = Vec::with_capacity(config.peers.len());
        for peer in config.peers {
            dialer_tasks.push(tokio::spawn(run_dialer(peer, inner.clone())));
        }
        Ok(Self {
            inner,
            listener_task,
            dialer_tasks,
        })
    }

    /// `Arc<AtomicBool>` flipped `true` whenever ≥ 1 peer is connected.
    /// Share with `shade_api::admin::ReadinessProbes::set_peers_up`.
    #[must_use]
    pub fn peers_up_handle(&self) -> Arc<AtomicBool> {
        self.inner.peers_up.clone()
    }

    /// Snapshot of currently-connected peer `node_id`s. Used by the
    /// daemon to compute role distribution per channel — the eligible
    /// peer set is `[self.node_id] + this.peer_node_ids()`.
    pub async fn peer_node_ids(&self) -> Vec<String> {
        self.inner.peers.lock().await.keys().cloned().collect()
    }

    /// Broadcast an `Upsert` to every connected peer. Drops the frame
    /// silently if the peer's outbound queue is full — slow peers get
    /// disconnected and re-snapshot on reconnect (per CLAUDE.md sync
    /// model).
    pub async fn broadcast_upsert(&self, upsert: Upsert) {
        self.broadcast_frame(Frame::Upsert(upsert)).await;
    }

    /// Broadcast a `Delete` to every connected peer.
    pub async fn broadcast_delete(&self, delete: Delete) {
        self.broadcast_frame(Frame::Delete(delete)).await;
    }

    async fn broadcast_frame(&self, frame: Frame) {
        let peers = self.inner.peers.lock().await;
        for (node_id, tx) in peers.iter() {
            if let Err(e) = tx.try_send(frame.clone()) {
                warn!(peer = %node_id, error = %e, "mesh broadcast failed (slow peer?); peer will resnap on reconnect");
            }
        }
    }

    /// Stop the listener + every dialer. Drops are also fine; the
    /// tasks abort once their `JoinHandle`s drop.
    pub fn shutdown(self) {
        self.listener_task.abort();
        for task in self.dialer_tasks {
            task.abort();
        }
    }
}

async fn run_listener(listener: TcpListener, inner: Arc<HubInner>) {
    loop {
        let server_cfg = inner.server_config.clone();
        let stream = match accept_peer(&listener, server_cfg).await {
            Ok(s) => s,
            Err(err) => {
                warn!(error = %err, "mesh: accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let inner = inner.clone();
        tokio::spawn(async move {
            handle_inbound_peer(stream, inner).await;
        });
    }
}

async fn handle_inbound_peer(
    mut stream: crate::peer::PeerStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
    inner: Arc<HubInner>,
) {
    let cert_node_id = stream.peer_node_id.clone();
    let my_hello = make_hello(&inner);
    let _peer_hello = match run_handshake(&mut stream.tls, &cert_node_id, &my_hello).await {
        Ok(h) => h,
        Err(err) => {
            warn!(peer = %cert_node_id, error = %err, "mesh: inbound handshake failed");
            return;
        }
    };
    info!(peer = %cert_node_id, "mesh: inbound peer connected");
    drive_peer(stream.tls, cert_node_id, inner).await;
}

async fn run_dialer(peer: MeshPeer, inner: Arc<HubInner>) {
    let mut backoff = Duration::from_millis(500);
    let max_backoff = Duration::from_secs(30);
    loop {
        let cli_cfg = inner.client_config.clone();
        match dial_peer(peer.endpoint, &peer.node_id, &peer.node_id, cli_cfg).await {
            Ok(mut stream) => {
                let cert_node_id = stream.peer_node_id.clone();
                let my_hello = make_hello(&inner);
                if let Err(err) = run_handshake(&mut stream.tls, &cert_node_id, &my_hello).await {
                    warn!(peer = %peer.node_id, error = %err, "mesh: outbound handshake failed");
                    sleep_with_backoff(&mut backoff, max_backoff).await;
                    continue;
                }
                info!(peer = %peer.node_id, "mesh: outbound peer connected");
                drive_peer(stream.tls, cert_node_id, inner.clone()).await;
                // Connection ended; reset backoff and reconnect.
                backoff = Duration::from_millis(500);
            }
            Err(_) => {
                sleep_with_backoff(&mut backoff, max_backoff).await;
            }
        }
    }
}

async fn sleep_with_backoff(current: &mut Duration, max: Duration) {
    tokio::time::sleep(*current).await;
    *current = (*current * 2).min(max);
}

fn make_hello(inner: &HubInner) -> PeerHello {
    PeerHello {
        node_id: inner.node_id.clone(),
        proto_version: PROTO_VERSION,
        features: shade_proto::PeerFeatures::default(),
        clock_ms: shade_core::now_ms(),
        channels: inner.channels.clone(),
    }
}

async fn drive_peer<S>(stream: S, peer_node_id: String, inner: Arc<HubInner>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<Frame>(64);
    {
        let mut peers = inner.peers.lock().await;
        peers.insert(peer_node_id.clone(), tx);
        let count = inner.peer_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count > 0 {
            inner.peers_up.store(true, Ordering::Relaxed);
        }
    }
    let res: Result<(), PeerLoopError> =
        run_peer(stream, peer_node_id.clone(), inner.store.clone(), rx).await;
    if let Err(err) = res {
        warn!(peer = %peer_node_id, error = %err, "mesh: peer loop ended with error");
    }
    {
        let mut peers = inner.peers.lock().await;
        peers.remove(&peer_node_id);
        let count = inner
            .peer_count
            .fetch_sub(1, Ordering::Relaxed)
            .saturating_sub(1);
        if count == 0 {
            inner.peers_up.store(false, Ordering::Relaxed);
        }
    }
    debug!(peer = %peer_node_id, "mesh: peer disconnected");
}

// Suppress dead-code warning: HandshakeError is referenced via
// run_handshake.
#[allow(dead_code)]
fn _force_handshake_link(_e: HandshakeError) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{client_config, server_config, test_pki::TestPki};
    use shade_core::{FlagSet, NewUser};

    #[tokio::test]
    async fn two_node_mesh_replicates_user_via_snapshot() {
        let pki = TestPki::new();
        let cert_a = pki.issue("node-a");
        let cert_b = pki.issue("node-b");
        let ca = vec![pki.ca_cert_der.clone()];

        let (a_cert_s, a_key_s) = cert_a.pair();
        let (a_cert_c, a_key_c) = cert_a.pair();
        let (b_cert_s, b_key_s) = cert_b.pair();
        let (b_cert_c, b_key_c) = cert_b.pair();
        let server_a = Arc::new(server_config(ca.clone(), vec![a_cert_s], a_key_s).unwrap());
        let client_a = Arc::new(client_config(ca.clone(), vec![a_cert_c], a_key_c).unwrap());
        let server_b = Arc::new(server_config(ca.clone(), vec![b_cert_s], b_key_s).unwrap());
        let client_b = Arc::new(client_config(ca.clone(), vec![b_cert_c], b_key_c).unwrap());

        let store_a = Arc::new(Store::open_in_memory().unwrap());
        store_a.migrate().unwrap();
        let store_b = Arc::new(Store::open_in_memory().unwrap());
        store_b.migrate().unwrap();

        // Seed alice on A *before* the mesh comes up, so the snapshot
        // delivers her to B.
        shade_store::users::upsert(
            &store_a,
            &NewUser {
                handle: "alice".into(),
                password_hash: None,
                is_bot: false,
                global_flags: "+a".parse::<FlagSet>().unwrap(),
                comment: None,
                hosts: vec!["alice!*@*".into()],
            },
            "node-a",
        )
        .unwrap();

        // Pick free ports for each node.
        let port_a = get_free_port().await;
        let port_b = get_free_port().await;

        let hub_a = MeshHub::spawn(
            store_a.clone(),
            MeshHubConfig {
                node_id: "node-a".into(),
                listen_addr: format!("127.0.0.1:{port_a}").parse().unwrap(),
                server_config: server_a,
                client_config: client_a,
                peers: vec![MeshPeer {
                    node_id: "node-b".into(),
                    endpoint: format!("127.0.0.1:{port_b}").parse().unwrap(),
                }],
                channels: vec![],
            },
        )
        .await
        .unwrap();

        let hub_b = MeshHub::spawn(
            store_b.clone(),
            MeshHubConfig {
                node_id: "node-b".into(),
                listen_addr: format!("127.0.0.1:{port_b}").parse().unwrap(),
                server_config: server_b,
                client_config: client_b,
                peers: vec![],
                channels: vec![],
            },
        )
        .await
        .unwrap();

        // Wait up to a few seconds for snapshot to land.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut found = false;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if shade_store::users::get_by_handle(&store_b, "alice")
                .unwrap()
                .is_some()
            {
                found = true;
                break;
            }
        }
        assert!(found, "alice should have replicated to node-b within 5s");
        assert!(hub_a.peers_up_handle().load(Ordering::Relaxed));
        assert!(hub_b.peers_up_handle().load(Ordering::Relaxed));

        hub_a.shutdown();
        hub_b.shutdown();
    }

    #[tokio::test]
    async fn broadcast_upsert_propagates_to_connected_peer() {
        let pki = TestPki::new();
        let cert_a = pki.issue("node-a");
        let cert_b = pki.issue("node-b");
        let ca = vec![pki.ca_cert_der.clone()];

        let (a_cert_s, a_key_s) = cert_a.pair();
        let (a_cert_c, a_key_c) = cert_a.pair();
        let (b_cert_s, b_key_s) = cert_b.pair();
        let (b_cert_c, b_key_c) = cert_b.pair();
        let server_a = Arc::new(server_config(ca.clone(), vec![a_cert_s], a_key_s).unwrap());
        let client_a = Arc::new(client_config(ca.clone(), vec![a_cert_c], a_key_c).unwrap());
        let server_b = Arc::new(server_config(ca.clone(), vec![b_cert_s], b_key_s).unwrap());
        let client_b = Arc::new(client_config(ca.clone(), vec![b_cert_c], b_key_c).unwrap());

        let store_a = Arc::new(Store::open_in_memory().unwrap());
        store_a.migrate().unwrap();
        let store_b = Arc::new(Store::open_in_memory().unwrap());
        store_b.migrate().unwrap();

        let port_a = get_free_port().await;
        let port_b = get_free_port().await;

        let hub_a = MeshHub::spawn(
            store_a.clone(),
            MeshHubConfig {
                node_id: "node-a".into(),
                listen_addr: format!("127.0.0.1:{port_a}").parse().unwrap(),
                server_config: server_a,
                client_config: client_a,
                peers: vec![MeshPeer {
                    node_id: "node-b".into(),
                    endpoint: format!("127.0.0.1:{port_b}").parse().unwrap(),
                }],
                channels: vec![],
            },
        )
        .await
        .unwrap();

        let hub_b = MeshHub::spawn(
            store_b.clone(),
            MeshHubConfig {
                node_id: "node-b".into(),
                listen_addr: format!("127.0.0.1:{port_b}").parse().unwrap(),
                server_config: server_b,
                client_config: client_b,
                peers: vec![],
                channels: vec![],
            },
        )
        .await
        .unwrap();

        // Wait for connection to establish.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline
            && !hub_a.peers_up_handle().load(Ordering::Relaxed)
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(hub_a.peers_up_handle().load(Ordering::Relaxed));

        // Now write a user on A and broadcast.
        let user_a = shade_store::users::upsert(
            &store_a,
            &NewUser {
                handle: "bob".into(),
                password_hash: None,
                is_bot: false,
                global_flags: FlagSet::NONE,
                comment: None,
                hosts: vec![],
            },
            "node-a",
        )
        .unwrap();
        hub_a
            .broadcast_upsert(Upsert {
                kind: shade_proto::UpsertKind::User(user_a),
            })
            .await;

        // Wait for B to apply.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut found = false;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if shade_store::users::get_by_handle(&store_b, "bob")
                .unwrap()
                .is_some()
            {
                found = true;
                break;
            }
        }
        assert!(found, "bob should have replicated via Upsert broadcast");

        hub_a.shutdown();
        hub_b.shutdown();
    }

    async fn get_free_port() -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        port
    }
}
