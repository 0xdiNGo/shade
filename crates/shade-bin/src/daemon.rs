//! `shade run` async entry point.
//!
//! Wires up tracing, opens the SQLite store, spawns the IRC session, and
//! serves the admin and metrics HTTP listeners. The mesh ships in M4; until
//! it does, `peers_up` stays false and `/readyz` reports 503 until M4 lands.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use shade_api::admin::{AdminState, ReadinessProbes};
use shade_api::v1::ApiState;
use shade_ircd::{
    BackoffConfig, ConnectionConfig, ReadyHandle, SaslMechanism, Session, SessionConfig,
    SessionEvent, TlsMode, WriteRateConfig, Writer,
};

use crate::config::{Config, NetworkConfig, SaslConfig};
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
    let store = Arc::new(store);

    let readiness = ReadinessProbes::new();
    readiness.set_store_open(true);

    let session_config = build_session_config(&cfg.network)?;
    let ready_handle = ReadyHandle::from_arc(readiness.irc_connected_handle());
    let session = Session::spawn(session_config, ready_handle);
    let session_writer = session.writer();
    let session_task = tokio::spawn(drive_session(
        session,
        session_writer.clone(),
        store.clone(),
    ));

    let admin_router = shade_api::admin::router(AdminState {
        readiness: readiness.clone(),
    })
    .merge(shade_api::v1::router(ApiState {
        store: store.clone(),
        node_id: Arc::from(cfg.node.id.as_str()),
    }));
    let metrics_router = shade_api::metrics::router(metrics_handle);

    let admin = tokio::spawn(serve("admin", cfg.admin.listen, admin_router));
    let metrics = tokio::spawn(serve("metrics", cfg.metrics.listen, metrics_router));

    wait_for_shutdown().await?;

    tracing::info!("shutdown signal received, stopping listeners");
    admin.abort();
    metrics.abort();
    session_task.abort();

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

fn build_session_config(net: &NetworkConfig) -> Result<SessionConfig> {
    let server = net
        .servers
        .first()
        .ok_or_else(|| anyhow!("network.servers must have at least one entry"))?;
    let addr: SocketAddr = parse_server_addr(server)
        .with_context(|| format!("parsing IRC server endpoint `{server}`"))?;
    let server_name = server
        .rsplit_once(':')
        .map_or_else(|| server.clone(), |(host, _)| host.to_string());

    let tls = if net.tls {
        TlsMode::Tls {
            additional_roots: Vec::new(),
        }
    } else {
        TlsMode::Plain
    };

    let sasl = match &net.sasl {
        None => None,
        Some(SaslConfig::External) => Some(SaslMechanism::External {
            authzid: String::new(),
        }),
        Some(SaslConfig::Plain {
            username,
            password_env,
        }) => {
            let password = std::env::var(password_env)
                .with_context(|| format!("reading SASL password from ${password_env}"))?;
            Some(SaslMechanism::Plain {
                authzid: String::new(),
                username: username.clone(),
                password,
            })
        }
    };

    let mut desired_caps = net.caps.clone();
    if sasl.is_some() && !desired_caps.iter().any(|c| c == "sasl") {
        desired_caps.push("sasl".into());
    }

    Ok(SessionConfig {
        connection: ConnectionConfig {
            addr,
            server_name,
            tls,
            backoff: BackoffConfig::default(),
            write_rate: WriteRateConfig::default(),
        },
        nick: net.nick.clone(),
        ident: net.ident.clone(),
        realname: net.realname.clone(),
        desired_caps,
        sasl,
        channels: net.channels.clone(),
    })
}

/// Resolve an `ip:port` literal or fall back to a synchronous DNS lookup.
fn parse_server_addr(s: &str) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut iter = s
        .to_socket_addrs()
        .with_context(|| format!("resolving {s}"))?;
    iter.next()
        .ok_or_else(|| anyhow!("no addresses returned for {s}"))
}

async fn drive_session(mut session: Session, writer: Writer, store: Arc<shade_store::Store>) {
    while let Some(evt) = session.next_event().await {
        match evt {
            SessionEvent::Welcomed { nick } => {
                tracing::info!(%nick, "irc: registered");
            }
            SessionEvent::Joined {
                channel,
                nick,
                user,
                host,
                is_self,
            } => {
                if is_self {
                    tracing::info!(%channel, "irc: joined channel");
                    continue;
                }
                apply_join_policy(
                    &writer,
                    &store,
                    &channel,
                    &nick,
                    user.as_deref(),
                    host.as_deref(),
                )
                .await;
            }
            SessionEvent::SaslOutcome { succeeded } => {
                tracing::info!(succeeded, "irc: sasl outcome");
            }
            SessionEvent::Disconnected { reason, delay } => {
                tracing::warn!(%reason, delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX), "irc: disconnected");
            }
            SessionEvent::Privmsg { from, target, body } => {
                if let Some(reply) = ping_reply(&target, &body, from.as_deref()) {
                    if let Err(err) = writer.send(reply).await {
                        tracing::warn!(%err, "irc: !ping reply send failed");
                    }
                }
            }
            SessionEvent::Notice { .. } => {}
        }
    }
}

/// Run the on-JOIN policy for a peer:
///
/// 1. Check the channel's ban list — if the peer's hostmask matches, KICK
///    them with the ban reason.
/// 2. Otherwise, look the peer up by hostmask (passive identification).
///    If they're a known user with `+o` in this channel, MODE +o them.
///
/// All store calls are short-lived synchronous SQLite reads; we do them
/// inline. M5 will route op decisions through the role-distribution layer
/// so only the bot holding `ROLE_OP` actually sets the mode.
async fn apply_join_policy(
    writer: &Writer,
    store: &Arc<shade_store::Store>,
    channel: &str,
    nick: &str,
    user: Option<&str>,
    host: Option<&str>,
) {
    let host_string = format_host(nick, user, host);

    let chan = match shade_store::channels::get_by_name(store, channel) {
        Ok(Some(c)) => c,
        Ok(None) => return, // channel not under management; nothing to do
        Err(err) => {
            tracing::warn!(%err, %channel, "irc: store error looking up channel");
            return;
        }
    };

    // Ban check first — kicking takes precedence over auto-op.
    match shade_store::masks::match_ban(store, chan.id, &host_string) {
        Ok(Some(mask)) => {
            let reason = mask.reason.as_deref().unwrap_or("banned");
            let line = format!("KICK {channel} {nick} :{reason}");
            if let Err(err) = writer.send(line).await {
                tracing::warn!(%err, %channel, %nick, "irc: kick send failed");
            } else {
                tracing::info!(%channel, %nick, %host_string, mask = %mask.mask, "irc: kicked banned peer");
            }
            return;
        }
        Ok(None) => {}
        Err(err) => {
            tracing::warn!(%err, %channel, "irc: store error in ban check");
            return;
        }
    }

    // Identify by hostmask, then look up channel-specific flags.
    let user_record = match shade_store::users::match_by_host(store, &host_string) {
        Ok(Some(u)) => u,
        Ok(None) => return, // unknown peer; nothing to do
        Err(err) => {
            tracing::warn!(%err, "irc: store error in user identification");
            return;
        }
    };

    let chan_flags = match shade_store::channels::get_user_flags(store, chan.id, user_record.id) {
        Ok(Some(row)) => row.flags,
        Ok(None) => return, // user known but no per-channel flags here
        Err(err) => {
            tracing::warn!(%err, "irc: store error reading user flags");
            return;
        }
    };

    if chan_flags.contains_letter(shade_core::flags::USER_OP) {
        let line = format!("MODE {channel} +o {nick}");
        if let Err(err) = writer.send(line).await {
            tracing::warn!(%err, %channel, %nick, "irc: auto-op send failed");
        } else {
            tracing::info!(%channel, %nick, handle = %user_record.handle, "irc: auto-opped");
        }
    }
}

/// Reconstruct a `nick!user@host` string for hostmask matching. Falls
/// back to `nick!*@*` when user/host weren't known yet (which can happen
/// if a JOIN arrives before WHO has populated state).
fn format_host(nick: &str, user: Option<&str>, host: Option<&str>) -> String {
    let user = user.unwrap_or("*");
    let host = host.unwrap_or("*");
    format!("{nick}!{user}@{host}")
}

/// `!ping` → `pong` echo. Replies to the channel for channel messages,
/// and to the sender's nick for direct PMs. Returns `None` when the body
/// isn't `!ping` or the reply target can't be derived.
fn ping_reply(target: &str, body: &str, from: Option<&str>) -> Option<String> {
    if body.trim() != "!ping" {
        return None;
    }
    let reply_target = if target.starts_with('#') || target.starts_with('&') {
        target.to_string()
    } else {
        // Direct message: respond to the sender's nick (strip user@host).
        let from = from?;
        let nick = from.split_once('!').map_or(from, |(n, _)| n);
        nick.to_string()
    };
    Some(format!("PRIVMSG {reply_target} :pong"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_reply_in_channel_targets_channel() {
        assert_eq!(
            ping_reply("#shade-test", "!ping", Some("alice!u@h")).as_deref(),
            Some("PRIVMSG #shade-test :pong")
        );
    }

    #[test]
    fn ping_reply_in_pm_targets_sender_nick() {
        assert_eq!(
            ping_reply("shade", "!ping", Some("alice!u@h")).as_deref(),
            Some("PRIVMSG alice :pong")
        );
    }

    #[test]
    fn ping_reply_ignores_other_bodies() {
        assert!(ping_reply("#x", "hello", Some("a!u@h")).is_none());
        assert!(ping_reply("#x", "!pingfoo", Some("a!u@h")).is_none());
    }

    #[test]
    fn ping_reply_trims_whitespace() {
        assert_eq!(
            ping_reply("#x", "  !ping  ", Some("a!u@h")).as_deref(),
            Some("PRIVMSG #x :pong")
        );
    }

    #[test]
    fn parse_server_addr_handles_ipv4_literal() {
        let a = parse_server_addr("127.0.0.1:6697").unwrap();
        assert_eq!(a.port(), 6697);
    }
}
