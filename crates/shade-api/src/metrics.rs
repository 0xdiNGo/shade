//! Prometheus metrics exposition.
//!
//! Installs a `metrics` recorder process-wide and serves the snapshot at
//! `/metrics` over plain HTTP. Scrape this endpoint over the private network
//! (Wireguard, VPC, sidecar) — it is *not* mTLS-protected and intentionally
//! does not require auth.

use std::sync::OnceLock;

use axum::extract::State;
use axum::routing::get;
use axum::Router;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

static RECORDER_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the global Prometheus recorder. Idempotent; subsequent calls
/// return the same handle without reinstalling.
pub fn install_recorder() -> &'static PrometheusHandle {
    RECORDER_HANDLE.get_or_init(|| {
        PrometheusBuilder::new()
            .install_recorder()
            .expect("prometheus recorder install")
    })
}

/// Build the metrics router. The handle is cloned per request; cloning a
/// `PrometheusHandle` is cheap (an `Arc`).
pub fn router(handle: PrometheusHandle) -> Router {
    Router::new()
        .route("/metrics", get(scrape))
        .with_state(handle)
}

#[allow(clippy::unused_async)]
async fn scrape(State(handle): State<PrometheusHandle>) -> String {
    handle.render()
}
