//! Operator-facing admin router.
//!
//! At this milestone the router exposes only health probes; the resource CRUD
//! surface (users, channels, masks, peers, roles, audit) ships in M3 as the
//! store and domain model land.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tower_http::trace::TraceLayer;

/// Indicates which subsystems must be reporting healthy before the node is
/// considered ready to serve traffic.
///
/// All flags are `Arc<AtomicBool>` so subsystems can flip them at runtime
/// independently of the admin router. Cheap to clone.
#[derive(Clone, Debug, Default)]
pub struct ReadinessProbes {
    irc_connected: Arc<AtomicBool>,
    peers_up: Arc<AtomicBool>,
    store_open: Arc<AtomicBool>,
}

impl ReadinessProbes {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn irc_connected(&self) -> bool {
        self.irc_connected.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn peers_up(&self) -> bool {
        self.peers_up.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn store_open(&self) -> bool {
        self.store_open.load(Ordering::Relaxed)
    }

    pub fn set_irc_connected(&self, value: bool) {
        self.irc_connected.store(value, Ordering::Relaxed);
    }

    pub fn set_peers_up(&self, value: bool) {
        self.peers_up.store(value, Ordering::Relaxed);
    }

    pub fn set_store_open(&self, value: bool) {
        self.store_open.store(value, Ordering::Relaxed);
    }

    /// Cheap clone of just the `irc_connected` flag, suitable for handing
    /// to a long-running task that only needs to flip that one bit.
    #[must_use]
    pub fn irc_connected_handle(&self) -> Arc<AtomicBool> {
        self.irc_connected.clone()
    }

    /// Cheap clone of just the `peers_up` flag. The mesh hub maintains
    /// its own atomic and the daemon mirrors it into this one for the
    /// `/readyz` probe.
    #[must_use]
    pub fn peers_up_handle(&self) -> Arc<AtomicBool> {
        self.peers_up.clone()
    }
}

#[derive(Clone, Debug)]
pub struct AdminState {
    pub readiness: ReadinessProbes,
}

/// Build the admin router. Concrete state will grow as M3 lands; today we
/// only use `readiness` for `/readyz`.
pub fn router(state: AdminState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

#[derive(Serialize)]
struct HealthBody {
    ok: bool,
}

async fn healthz() -> Json<HealthBody> {
    Json(HealthBody { ok: true })
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)] // serialized DTO; matches the JSON shape we want.
struct ReadyBody {
    ok: bool,
    irc_connected: bool,
    peers_up: bool,
    store_open: bool,
}

async fn readyz(
    axum::extract::State(state): axum::extract::State<AdminState>,
) -> (StatusCode, Json<ReadyBody>) {
    let probes = &state.readiness;
    let irc_connected = probes.irc_connected();
    let peers_up = probes.peers_up();
    let store_open = probes.store_open();
    let ok = irc_connected && peers_up && store_open;
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = ReadyBody {
        ok,
        irc_connected,
        peers_up,
        store_open,
    };
    (status, Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    fn router_for(probes: ReadinessProbes) -> Router {
        router(AdminState { readiness: probes })
    }

    async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn healthz_always_ok() {
        let app = router_for(ReadinessProbes::new());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["ok"], true);
    }

    #[tokio::test]
    async fn readyz_503_when_subsystems_down() {
        let app = router_for(ReadinessProbes::new());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(resp).await;
        assert_eq!(body["ok"], false);
        assert_eq!(body["irc_connected"], false);
    }

    #[tokio::test]
    async fn readyz_200_when_all_up() {
        let probes = ReadinessProbes::new();
        probes.set_irc_connected(true);
        probes.set_peers_up(true);
        probes.set_store_open(true);
        let app = router_for(probes);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["ok"], true);
    }

    #[tokio::test]
    async fn readyz_reflects_runtime_flips() {
        let probes = ReadinessProbes::new();
        probes.set_store_open(true);
        let app = router_for(probes.clone());

        // Not ready yet: only store_open is true.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Flip the remaining probes after the router was built.
        probes.set_irc_connected(true);
        probes.set_peers_up(true);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["irc_connected"], true);
    }
}
