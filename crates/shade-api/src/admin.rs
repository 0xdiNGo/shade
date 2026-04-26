//! Operator-facing admin router.
//!
//! At this milestone the router exposes only health probes; the resource CRUD
//! surface (users, channels, masks, peers, roles, audit) ships in M3 as the
//! store and domain model land.

use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tower_http::trace::TraceLayer;

/// Indicates which subsystems must be reporting healthy before the node is
/// considered ready to serve traffic.
#[derive(Clone, Debug, Default)]
pub struct ReadinessProbes {
    pub irc_connected: bool,
    pub peers_up: bool,
    pub store_open: bool,
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
    let ok = probes.irc_connected && probes.peers_up && probes.store_open;
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = ReadyBody {
        ok,
        irc_connected: probes.irc_connected,
        peers_up: probes.peers_up,
        store_open: probes.store_open,
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

    fn router_with_probes(p: ReadinessProbes) -> Router {
        router(AdminState { readiness: p })
    }

    async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn healthz_always_ok() {
        let app = router_with_probes(ReadinessProbes::default());
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
        let app = router_with_probes(ReadinessProbes::default());
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
        let app = router_with_probes(ReadinessProbes {
            irc_connected: true,
            peers_up: true,
            store_open: true,
        });
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
}
