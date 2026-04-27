//! `shade run` async entry point.
//!
//! Wires up tracing, opens the SQLite store, spawns the IRC session, brings
//! the mTLS mesh online (when the node's TLS material is present), and
//! serves the admin and metrics HTTP listeners.

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use shade_api::admin::{AdminState, ReadinessProbes};
use shade_api::v1::ApiState;
use shade_ircd::{
    BackoffConfig, ConnectionConfig, ReadyHandle, SaslMechanism, Session, SessionConfig,
    SessionEvent, TlsMode, WriteRateConfig, Writer,
};
use shade_mesh::{MeshHub, MeshHubConfig, MeshPeer};

use crate::config::{Config, NetworkConfig, SaslConfig, TlsConfig};
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

    // Mesh — optional. If the node's TLS material isn't on disk yet,
    // log and stay single-node. This keeps the M3 demo path
    // (docker compose without certs) running unchanged.
    let mesh = setup_mesh(&cfg, &store, &readiness).await?;

    // Build the role context that drives ROLE_OP / cookie decisions
    // when the mesh is online. Without it the daemon falls back to
    // M3-style "always op."
    let role_ctx = match (&mesh, std::env::var(&cfg.mesh.psk_env)) {
        (Some(hub), Ok(psk)) => Some(RoleContext {
            node_id: Arc::from(cfg.node.id.as_str()),
            mesh: hub.clone(),
            mesh_psk: Arc::from(psk.into_bytes().into_boxed_slice()),
        }),
        (Some(_), Err(_)) => {
            tracing::warn!(
                env = %cfg.mesh.psk_env,
                "mesh online but ${} is unset — cookie ops disabled, role decisions still apply",
                cfg.mesh.psk_env,
            );
            None
        }
        (None, _) => None,
    };

    let session_task = tokio::spawn(drive_session(
        session,
        session_writer.clone(),
        store.clone(),
        role_ctx.clone(),
    ));

    let admin_router = shade_api::admin::router(AdminState {
        readiness: readiness.clone(),
    })
    .merge(shade_api::v1::router(ApiState {
        store: store.clone(),
        node_id: Arc::from(cfg.node.id.as_str()),
        mesh: mesh.clone(),
    }));
    let metrics_router = shade_api::metrics::router(metrics_handle);

    let admin = spawn_admin_listener(&cfg, admin_router)?;
    let metrics = tokio::spawn(serve("metrics", cfg.metrics.listen, metrics_router));

    wait_for_shutdown().await?;

    tracing::info!("shutdown signal received, stopping listeners");
    admin.abort();
    metrics.abort();
    session_task.abort();
    if let Some(hub) = mesh {
        if let Ok(hub) = Arc::try_unwrap(hub) {
            hub.shutdown();
        }
    }

    Ok(())
}

async fn setup_mesh(
    cfg: &Config,
    store: &Arc<shade_store::Store>,
    readiness: &ReadinessProbes,
) -> Result<Option<Arc<MeshHub>>> {
    let tls = &cfg.node.tls;
    if !pem_files_present(tls) {
        tracing::warn!(
            ca_bundle = %tls.ca_bundle.display(),
            cert = %tls.cert.display(),
            key = %tls.key.display(),
            "mesh: TLS material missing — staying single-node. \
             run `shade init-ca` + `shade issue-cert --node-id {}` to bring mesh online.",
            cfg.node.id,
        );
        return Ok(None);
    }

    let ca_bundle = read_pem_certs(&tls.ca_bundle)?;
    let cert_chain = read_pem_certs(&tls.cert)?;
    let key = read_pem_key(&tls.key)?;
    let server_config = Arc::new(
        shade_mesh::server_config(ca_bundle.clone(), cert_chain.clone(), clone_key(&tls.key)?)
            .map_err(|e| anyhow!("server TLS config: {e}"))?,
    );
    let client_config = Arc::new(
        shade_mesh::client_config(ca_bundle, cert_chain, key)
            .map_err(|e| anyhow!("client TLS config: {e}"))?,
    );

    let peers = cfg
        .mesh
        .peers
        .iter()
        .map(|p| MeshPeer {
            node_id: p.node_id.clone(),
            endpoint: p.endpoint,
        })
        .collect();

    let hub = MeshHub::spawn(
        store.clone(),
        MeshHubConfig {
            node_id: cfg.node.id.clone(),
            listen_addr: cfg.mesh.listen,
            server_config,
            client_config,
            peers,
            channels: cfg.network.channels.clone(),
        },
    )
    .await
    .with_context(|| format!("starting mesh listener on {}", cfg.mesh.listen))?;

    // Share peers_up with /readyz.
    let probe = readiness.peers_up_handle();
    let live = hub.peers_up_handle();
    tokio::spawn(async move {
        loop {
            probe.store(
                live.load(std::sync::atomic::Ordering::Relaxed),
                std::sync::atomic::Ordering::Relaxed,
            );
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });

    Ok(Some(Arc::new(hub)))
}

fn pem_files_present(tls: &TlsConfig) -> bool {
    tls.ca_bundle.exists() && tls.cert.exists() && tls.key.exists()
}

fn read_pem_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let pem =
        fs::read_to_string(path).with_context(|| format!("reading PEM at {}", path.display()))?;
    let mut out = Vec::new();
    for block in pem::parse_many(pem.as_bytes())
        .with_context(|| format!("parsing PEM at {}", path.display()))?
    {
        if block.tag().eq_ignore_ascii_case("CERTIFICATE") {
            out.push(rustls::pki_types::CertificateDer::from(
                block.contents().to_vec(),
            ));
        }
    }
    if out.is_empty() {
        return Err(anyhow!(
            "no CERTIFICATE blocks in PEM at {}",
            path.display()
        ));
    }
    Ok(out)
}

fn read_pem_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let pem = fs::read_to_string(path)
        .with_context(|| format!("reading key PEM at {}", path.display()))?;
    for block in pem::parse_many(pem.as_bytes())
        .with_context(|| format!("parsing key PEM at {}", path.display()))?
    {
        let tag = block.tag();
        if tag.eq_ignore_ascii_case("PRIVATE KEY") || tag.eq_ignore_ascii_case("PKCS8 PRIVATE KEY")
        {
            return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                block.contents().to_vec(),
            )));
        }
    }
    Err(anyhow!(
        "no PKCS#8 PRIVATE KEY block in PEM at {}",
        path.display()
    ))
}

fn clone_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    read_pem_key(path)
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

/// Decide between the mTLS admin listener and the plain-TCP fallback.
///
/// If `admin.require_mtls` is true and the operator-CA bundle + server
/// cert/key are on disk, bring up the rustls accept loop. Otherwise log
/// loudly and fall back to plain TCP — fine for tests but a configuration
/// error in production.
fn spawn_admin_listener(
    cfg: &Config,
    router: axum::Router,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let admin = &cfg.admin;
    let server_cert_path = admin
        .server_cert
        .as_deref()
        .unwrap_or(cfg.node.tls.cert.as_path());
    let server_key_path = admin
        .server_key
        .as_deref()
        .unwrap_or(cfg.node.tls.key.as_path());

    if !admin.require_mtls {
        tracing::warn!(
            addr = %admin.listen,
            "admin: require_mtls=false — serving plain HTTP (development only)"
        );
        return Ok(tokio::spawn(serve("admin", admin.listen, router)));
    }

    if !crate::admin_tls::admin_tls_present(admin, server_cert_path) {
        tracing::warn!(
            client_ca = %admin.client_ca.display(),
            cert = %server_cert_path.display(),
            key = %server_key_path.display(),
            "admin: require_mtls=true but PKI material missing — falling back to plain HTTP. \
             run `shade init-ca` + `shade issue-cert` + `shade issue-admin-cert` to bring mTLS online."
        );
        return Ok(tokio::spawn(serve("admin", admin.listen, router)));
    }

    let client_ca = read_pem_certs(&admin.client_ca)?;
    let cert_chain = read_pem_certs(server_cert_path)?;
    let key = read_pem_key(server_key_path)?;
    let server_config = crate::admin_tls::build_server_config(client_ca, cert_chain, key)?;

    let listen = admin.listen;
    Ok(tokio::spawn(async move {
        crate::admin_tls::serve_admin_tls(listen, server_config, router).await
    }))
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

async fn drive_session(
    mut session: Session,
    writer: Writer,
    store: Arc<shade_store::Store>,
    role_ctx: Option<RoleContext>,
) {
    let mut op_observer = crate::op_observer::OpObserver::new();
    let observer_ctx = role_ctx
        .as_ref()
        .map(|r| crate::op_observer::ObserverContext {
            node_id: r.node_id.clone(),
            mesh_psk: r.mesh_psk.clone(),
        });
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
                    role_ctx.as_ref(),
                    &channel,
                    &nick,
                    user.as_deref(),
                    host.as_deref(),
                )
                .await;
            }
            SessionEvent::ModeChanged {
                target,
                by,
                modes,
                args,
            } => {
                // Track every observed +o for cookie verification +
                // mass-op detection. Walk the mode chars + args side
                // by side; only +o consumes an arg here, since other
                // arg-bearing modes (b/e/I/k/l) aren't ops.
                if !target.starts_with('#') && !target.starts_with('&') {
                    continue;
                }
                let now = shade_core::now_ms();
                let mut adding = true;
                let mut arg_idx = 0;
                let mut actions: Vec<crate::op_observer::MassOpAction> = Vec::new();
                for c in modes.chars() {
                    match c {
                        '+' => adding = true,
                        '-' => adding = false,
                        'o' if adding => {
                            if let Some(target_nick) = args.get(arg_idx) {
                                if let Some(a) =
                                    op_observer.record_op(&target, target_nick, &by, now)
                                {
                                    actions.push(a);
                                }
                            }
                            arg_idx += 1;
                        }
                        'o' | 'v' => {
                            arg_idx += 1;
                        }
                        'b' | 'e' | 'I' | 'k' => arg_idx += 1,
                        'l' if adding => arg_idx += 1,
                        _ => {}
                    }
                }
                op_observer.maybe_sweep(now);
                for action in actions {
                    apply_mass_op_response(&writer, &store, role_ctx.as_ref(), &action).await;
                }
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
            SessionEvent::Notice { target, body, .. } => {
                if let (Some(wire), Some(ctx)) = (
                    crate::op_observer::extract_cookie_wire(&body),
                    observer_ctx.as_ref(),
                ) {
                    let now = shade_core::now_ms();
                    op_observer.record_cookie_notice(&target, wire, ctx, now);
                }
            }
        }
    }
}

/// Per-channel role context the daemon needs to make op decisions.
#[derive(Clone)]
pub struct RoleContext {
    pub node_id: Arc<str>,
    pub mesh: Arc<shade_mesh::MeshHub>,
    /// HKDF-input keying material for cookie derivation (the mesh PSK).
    pub mesh_psk: Arc<[u8]>,
}

impl std::fmt::Debug for RoleContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleContext")
            .field("node_id", &self.node_id)
            .field("psk_len", &self.mesh_psk.len())
            .finish_non_exhaustive()
    }
}

/// Run the on-JOIN policy for a peer:
///
/// 1. Check the channel's ban list — if the peer's hostmask matches, KICK
///    them with the ban reason.
/// 2. Otherwise, look the peer up by hostmask (passive identification).
///    If they're a known user with `+o` in this channel:
///    - **With mesh online**: compute the role assignment from
///      `[self] + connected_peers`. Issue the MODE only if we hold
///      `ROLE_OP` for this channel; otherwise log and let the holder
///      issue it. Embed an HMAC-SHA256 cookie NOTICE so other Shade
///      bots can verify the authorization.
///    - **Single-node** (no `RoleContext`): always issue. Same
///      behavior as M3 for the dev-only single-bot demo.
///
/// All store calls are short-lived synchronous SQLite reads; we do them
/// inline.
async fn apply_join_policy(
    writer: &Writer,
    store: &Arc<shade_store::Store>,
    role_ctx: Option<&RoleContext>,
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

    if !chan_flags.contains_letter(shade_core::flags::USER_OP) {
        return;
    }

    // Decide: do we hold ROLE_OP for this channel? When the mesh is
    // online, only the role holder issues. When not, fall back to
    // "always op" so the M3 single-node demo path still works.
    if let Some(ctx) = role_ctx {
        let mut peers: Vec<String> = ctx.mesh.peer_node_ids().await;
        peers.push(ctx.node_id.to_string());
        let assignment = shade_core::compute_assignment(&peers);
        let i_hold_op = assignment
            .get(&shade_core::Role::Op)
            .is_some_and(|holders| holders.iter().any(|h| h.as_str() == &*ctx.node_id));
        if !i_hold_op {
            tracing::debug!(
                %channel, %nick,
                holders = ?assignment.get(&shade_core::Role::Op),
                "irc: not the ROLE_OP holder for this channel; deferring"
            );
            return;
        }
        // Issue the op + cookie NOTICE.
        issue_op_with_cookie(writer, ctx, channel, nick).await;
    } else {
        let line = format!("MODE {channel} +o {nick}");
        if let Err(err) = writer.send(line).await {
            tracing::warn!(%err, %channel, %nick, "irc: auto-op send failed");
        } else {
            tracing::info!(%channel, %nick, handle = %user_record.handle, "irc: auto-opped (single-node)");
        }
    }
}

/// Reverse a mass-op event by sending `MODE -o` for every observed
/// victim and writing one audit row.
///
/// **Role gating.** When the mesh is online, only the deterministic
/// `ROLE_OP` holder for the channel issues the deop — same rule as
/// `apply_join_policy`. This avoids the entire mesh blasting `-o`
/// modes simultaneously when one Shade peer trips on a flood.
///
/// **Single-node fallback.** Without a `RoleContext` (no mesh, M3-style
/// demo) the daemon issues the deop directly. There's no role conflict
/// to worry about.
///
/// **Audit.** A single `mass_op.deop` entry is written with the
/// rogue source + victim list in `details`. We do *not* broadcast a
/// mesh frame for the action — peers see the `-o` over IRC and can
/// reach the same conclusion independently.
async fn apply_mass_op_response(
    writer: &Writer,
    store: &Arc<shade_store::Store>,
    role_ctx: Option<&RoleContext>,
    action: &crate::op_observer::MassOpAction,
) {
    let crate::op_observer::MassOpAction::Deop {
        channel,
        source,
        victims,
    } = action;

    if let Some(ctx) = role_ctx {
        let mut peers: Vec<String> = ctx.mesh.peer_node_ids().await;
        peers.push(ctx.node_id.to_string());
        let assignment = shade_core::compute_assignment(&peers);
        let i_hold_op = assignment
            .get(&shade_core::Role::Op)
            .is_some_and(|holders| holders.iter().any(|h| h.as_str() == &*ctx.node_id));
        if !i_hold_op {
            tracing::info!(
                %channel, %source,
                victim_count = victims.len(),
                "mass-op response observed; not the ROLE_OP holder, deferring"
            );
            return;
        }
    }

    // Send one MODE per victim. No batching — keep it simple, the
    // mode_queue already rate-limits outbound writes.
    for victim in victims {
        let line = format!("MODE {channel} -o {victim}");
        if let Err(err) = writer.send(line).await {
            tracing::warn!(%err, %channel, %victim, "mass-op deop send failed");
        }
    }

    let entry = shade_core::AuditEntry::new(
        shade_core::now_ms(),
        format!("op-observer@{channel}"),
        "mass_op.deop",
        shade_core::AuditSource::System,
    )
    .with_target(channel)
    .with_details(serde_json::json!({
        "source": source,
        "victims": victims,
    }));
    if let Err(err) = shade_store::audit::insert(store, &entry) {
        tracing::warn!(%err, "mass-op deop audit insert failed");
    }
    tracing::warn!(
        %channel, %source, victim_count = victims.len(),
        "mass-op response: deopped all recently-opped victims"
    );
}

/// Issue `MODE +o nick` plus a `NOTICE shade-cookie/<wire>` so other
/// Shade bots on the channel can cryptographically verify the op was
/// authorized by the deterministic ROLE_OP holder.
async fn issue_op_with_cookie(writer: &Writer, ctx: &RoleContext, channel: &str, nick: &str) {
    let key = shade_core::derive_channel_key(&ctx.mesh_psk, channel);
    let cookie = shade_core::Cookie::new((*ctx.node_id).to_owned(), nick.to_owned());
    let Some(wire) = shade_core::cookies::make(&cookie, &key) else {
        tracing::warn!(%channel, %nick, "irc: failed to mint cookie; not opping");
        return;
    };
    // Op first, then proof. Other bots seeing the op without a matching
    // cookie within ~1s will mark it as suspicious in M5 PR3.
    let mode_line = format!("MODE {channel} +o {nick}");
    let cookie_line = format!("NOTICE {channel} :shade-cookie/{wire}");
    if let Err(err) = writer.send(mode_line).await {
        tracing::warn!(%err, %channel, %nick, "irc: auto-op send failed");
        return;
    }
    if let Err(err) = writer.send(cookie_line).await {
        tracing::warn!(%err, %channel, %nick, "irc: cookie NOTICE send failed");
        return;
    }
    tracing::info!(%channel, %nick, "irc: auto-opped with cookie (ROLE_OP holder)");
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
