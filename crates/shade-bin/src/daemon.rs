//! `shade run` async entry point.
//!
//! Wires up tracing, installs the Prometheus recorder, and serves the admin
//! and metrics HTTP listeners. mTLS, the IRC client, and the mesh ship in
//! later PRs; until they do, `/readyz` returns 503.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use shade_api::admin::{AdminState, ReadinessProbes};

use crate::config::Config;
use crate::telemetry;

/// Run the Shade daemon until it receives Ctrl-C or SIGTERM.
pub async fn run(cfg: Config) -> Result<()> {
    telemetry::init(&cfg.logging).context("initializing tracing")?;

    let metrics_handle = shade_api::metrics::install_recorder().clone();

    tracing::info!(
        node_id = %cfg.node.id,
        admin_listen = %cfg.admin.listen,
        metrics_listen = %cfg.metrics.listen,
        "starting shade"
    );

    std::fs::create_dir_all(&cfg.node.data_dir)
        .with_context(|| format!("creating {}", cfg.node.data_dir.display()))?;
    let db_path = shade_store::db_path_in(&cfg.node.data_dir);
    let store = shade_store::Store::open(&db_path)
        .with_context(|| format!("opening {}", db_path.display()))?;
    let report = store
        .migrate()
        .with_context(|| format!("migrating {}", db_path.display()))?;
    store.probe().context("probing store")?;
    tracing::info!(
        db_path = %db_path.display(),
        migrations_applied = report.applied,
        "store opened"
    );

    let admin_router = shade_api::admin::router(AdminState {
        readiness: ReadinessProbes {
            store_open: true,
            ..ReadinessProbes::default()
        },
    });
    let metrics_router = shade_api::metrics::router(metrics_handle);

    let admin = tokio::spawn(serve("admin", cfg.admin.listen, admin_router));
    let metrics = tokio::spawn(serve("metrics", cfg.metrics.listen, metrics_router));

    wait_for_shutdown().await?;

    tracing::info!("shutdown signal received, stopping listeners");
    admin.abort();
    metrics.abort();

    Ok(())
}

#[tracing::instrument(skip(router))]
async fn serve(name: &'static str, addr: SocketAddr, router: axum::Router) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {name} listener on {addr}"))?;
    tracing::info!(%addr, "{name} listener bound");
    axum::serve(listener, router)
        .await
        .with_context(|| format!("{name} server"))?;
    Ok(())
}

async fn wait_for_shutdown() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            res.context("ctrl-c handler")?;
            tracing::info!("received Ctrl-C");
        }
        _ = sigterm.recv() => {
            tracing::info!("received SIGTERM");
        }
    }
    Ok(())
}
