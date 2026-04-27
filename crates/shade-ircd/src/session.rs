//! IRC session loop: ties [`Connection`], [`CapNegotiation`], [`SaslMechanism`],
//! [`ServerState`], and [`ModeQueue`] together into a single async runner.
//!
//! Spawn a [`Session`] from a [`SessionConfig`]. The runner drives one IRC
//! session at a time:
//!
//! 1. Open the TCP+TLS connection (delegated to [`Connection`]).
//! 2. On `Connected`, send `CAP LS 302`, then `NICK` and `USER`.
//! 3. Drive [`CapNegotiation`] from incoming `CAP` lines. If `sasl` is acked
//!    and a [`SaslMechanism`] is configured, run the `AUTHENTICATE` flow;
//!    otherwise (or after SASL completes) send `CAP END`.
//! 4. Feed every parsed line into [`ServerState`]; on `RPL_WELCOME`, mark
//!    [`ReadyHandle`] true and auto-join the configured channels.
//! 5. Reply to server `PING` with `PONG`.
//! 6. On a 250ms tick, flush every [`ModeQueue`] bucket through the writer.
//!
//! State that survives disconnects: nothing. A reconnect re-runs the dance
//! from step 2; [`ServerState`] and [`ModeQueue`] are reset because the
//! server's view is being re-established.
//!
//! What this file owns vs. what its consumer owns: the session task owns
//! every async detail of the IRC dance. Higher-level Shade behavior (auto-op
//! on join, kick-on-mask, mesh-driven role handoff) lives outside; the
//! session emits [`SessionEvent`]s for the consumer to react to.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::caps::{CapAction, CapNegotiation};
use crate::connection::{Connection, ConnectionConfig, ConnectionEvent, Writer};
use crate::message::Command;
use crate::mode_queue::ModeQueue;
use crate::parser::parse_str;
use crate::sasl::{authenticate_start, sasl_authenticate_lines, SaslMechanism};
use crate::state::{ServerState, StateEvent};

/// Inputs needed to drive one IRC session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Underlying connection settings (addr, TLS posture, backoff, rate).
    pub connection: ConnectionConfig,
    /// Initial nickname requested via `NICK`.
    pub nick: String,
    /// Username field of `USER`.
    pub ident: String,
    /// Realname field of `USER` (the IRC `:realname` trailing param).
    pub realname: String,
    /// Capabilities we'll request via `CAP REQ` if the server advertises
    /// them in `CAP LS`.
    pub desired_caps: Vec<String>,
    /// SASL mechanism + credentials. `None` skips SASL even if `sasl` is
    /// in `desired_caps` and acked.
    pub sasl: Option<SaslMechanism>,
    /// Channels to `JOIN` once `RPL_WELCOME` is received.
    pub channels: Vec<String>,
}

/// Cheap, cloneable handle the rest of the daemon checks for the
/// "IRC connected" readiness probe. Set to `true` on `RPL_WELCOME`, back
/// to `false` on disconnect. Wraps an `Arc<AtomicBool>` so the same
/// underlying flag can be shared with `shade-api`'s `ReadinessProbes`.
#[derive(Clone, Debug, Default)]
pub struct ReadyHandle {
    flag: Arc<AtomicBool>,
}

impl ReadyHandle {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap an existing `Arc<AtomicBool>`. Lets the daemon share a single
    /// flag between `ReadinessProbes::irc_connected_handle` and the IRC
    /// session.
    #[must_use]
    pub fn from_arc(flag: Arc<AtomicBool>) -> Self {
        Self { flag }
    }

    /// Whether the session has reached `RPL_WELCOME` since the last
    /// disconnect.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    fn set(&self, value: bool) {
        self.flag.store(value, Ordering::Relaxed);
    }
}

/// High-level events the session emits for consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// `RPL_WELCOME` received; bot is registered as `nick`.
    Welcomed { nick: String },
    /// A `PRIVMSG` was delivered.
    Privmsg {
        from: Option<String>,
        target: String,
        body: String,
    },
    /// A `NOTICE` was delivered.
    Notice {
        from: Option<String>,
        target: String,
        body: String,
    },
    /// Someone joined a channel — including us, distinguished by
    /// `is_self`. The fields mirror `Member` so consumers can run policy
    /// (auto-op, auto-kick) without re-querying state.
    Joined {
        channel: String,
        nick: String,
        user: Option<String>,
        host: Option<String>,
        is_self: bool,
    },
    /// SASL succeeded (`903 RPL_SASLSUCCESS`) or was skipped because
    /// either the cap wasn't acked or no mechanism was configured.
    SaslOutcome { succeeded: bool },
    /// Underlying connection dropped; the runner will reconnect after
    /// `delay`.
    Disconnected { reason: String, delay: Duration },
}

/// Spawned session runner.
///
/// Drop or call [`Session::shutdown`] to stop. The writer handle is
/// cloneable; lines sent through it respect the underlying connection's
/// rate limiter.
pub struct Session {
    events: mpsc::Receiver<SessionEvent>,
    writer: Writer,
    handle: JoinHandle<()>,
}

impl Session {
    /// Spawn the session runner. The provided [`ReadyHandle`] is updated
    /// on `RPL_WELCOME` (true) and on each disconnect (false).
    #[must_use]
    pub fn spawn(config: SessionConfig, ready: ReadyHandle) -> Self {
        let connection = Connection::spawn(config.connection.clone());
        let writer = connection.writer();
        let (event_tx, event_rx) = mpsc::channel(64);
        let writer_for_task = writer.clone();
        let handle = tokio::spawn(run(connection, writer_for_task, config, ready, event_tx));
        Self {
            events: event_rx,
            writer,
            handle,
        }
    }

    /// Cloneable writer handle. Useful for wire-up of consumer logic
    /// (e.g. a `!ping` handler that needs to reply with `PRIVMSG`).
    #[must_use]
    pub fn writer(&self) -> Writer {
        self.writer.clone()
    }

    /// Receive the next session event. Returns `None` once the runner
    /// has terminated.
    pub async fn next_event(&mut self) -> Option<SessionEvent> {
        self.events.recv().await
    }

    /// Stop the runner. The runner reconnects forever by design, so we
    /// abort its task rather than waiting for it to drain naturally.
    pub async fn shutdown(self) {
        self.handle.abort();
        let _ = self.handle.await;
    }
}

async fn run(
    mut connection: Connection,
    writer: Writer,
    config: SessionConfig,
    ready: ReadyHandle,
    events: mpsc::Sender<SessionEvent>,
) {
    let mut runner = Runner::new(&config, &writer, &ready, &events);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            evt = connection.next_event() => {
                let Some(evt) = evt else { return; };
                runner.handle_connection_event(evt).await;
            }
            _ = tick.tick() => {
                runner.flush_mode_queue().await;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Pre-connect; nothing has been sent yet.
    Disconnected,
    /// `CAP LS 302` + `NICK` + `USER` have been sent. We're collecting
    /// `CAP * LS` lines and will eventually `CAP REQ` (or jump straight to
    /// `CAP END` on no-overlap).
    NegotiatingCaps,
    /// `CAP REQ` was acked for `sasl` and we've kicked off the
    /// `AUTHENTICATE` flow.
    AuthenticatingSasl,
    /// `CAP END` sent (with or without SASL) and we're waiting for
    /// `RPL_WELCOME`.
    AwaitingWelcome,
    /// `RPL_WELCOME` received.
    Registered,
}

struct Runner<'a> {
    config: &'a SessionConfig,
    writer: &'a Writer,
    ready: &'a ReadyHandle,
    events: &'a mpsc::Sender<SessionEvent>,
    caps: CapNegotiation,
    state: ServerState,
    mode_queue: ModeQueue,
    phase: Phase,
}

impl<'a> Runner<'a> {
    fn new(
        config: &'a SessionConfig,
        writer: &'a Writer,
        ready: &'a ReadyHandle,
        events: &'a mpsc::Sender<SessionEvent>,
    ) -> Self {
        Self {
            config,
            writer,
            ready,
            events,
            caps: CapNegotiation::new(config.desired_caps.iter().cloned()),
            state: ServerState::new(),
            mode_queue: ModeQueue::new(),
            phase: Phase::Disconnected,
        }
    }

    fn reset_for_reconnect(&mut self) {
        self.caps = CapNegotiation::new(self.config.desired_caps.iter().cloned());
        self.state = ServerState::new();
        self.mode_queue = ModeQueue::new();
        self.phase = Phase::Disconnected;
        self.ready.set(false);
    }

    async fn handle_connection_event(&mut self, evt: ConnectionEvent) {
        match evt {
            ConnectionEvent::Connected => {
                info!("session: connected, starting registration");
                self.phase = Phase::NegotiatingCaps;
                self.send(CapNegotiation::initial_command()).await;
                self.send(format!("NICK {}", self.config.nick)).await;
                self.send(format!(
                    "USER {} 0 * :{}",
                    self.config.ident, self.config.realname
                ))
                .await;
            }
            ConnectionEvent::Line(line) => self.handle_line(&line).await,
            ConnectionEvent::Disconnected { reason, delay } => {
                warn!(reason = %reason, delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX), "session: disconnected");
                self.reset_for_reconnect();
                let _ = self
                    .events
                    .send(SessionEvent::Disconnected { reason, delay })
                    .await;
            }
        }
    }

    async fn handle_line(&mut self, line: &str) {
        let msg = match parse_str(line) {
            Ok(m) => m,
            Err(err) => {
                debug!(error = %err, line = %line, "session: parse error, dropping line");
                return;
            }
        };

        // CAP first — it has phase implications even before registration.
        let cap_actions = self.caps.handle(&msg);
        for action in cap_actions {
            self.apply_cap_action(action).await;
        }

        // SASL phase consumes specific server messages.
        if self.phase == Phase::AuthenticatingSasl {
            self.drive_sasl(&msg).await;
        }

        // Then the state machine + transient handlers.
        let state_events = self.state.process(&msg);
        for evt in state_events {
            self.apply_state_event(evt).await;
        }
    }

    async fn apply_cap_action(&mut self, action: CapAction) {
        match action {
            CapAction::Send(line) => self.send(line).await,
            CapAction::Acked(_) | CapAction::Nakked(_) => {
                // Tracking is internal to CapNegotiation; nothing to do here.
            }
            CapAction::Done => self.handle_caps_done().await,
        }
    }

    async fn handle_caps_done(&mut self) {
        // Decide: SASL or straight to CAP END?
        if self.caps.sasl_acked() {
            if let Some(mech) = &self.config.sasl {
                debug!("session: starting SASL flow");
                self.phase = Phase::AuthenticatingSasl;
                self.send(authenticate_start(mech)).await;
                return;
            }
            warn!("session: server acked sasl but no mechanism is configured; ending caps");
        }
        self.finish_caps_with_no_sasl().await;
    }

    async fn finish_caps_with_no_sasl(&mut self) {
        let _ = self
            .events
            .send(SessionEvent::SaslOutcome { succeeded: false })
            .await;
        self.send("CAP END").await;
        self.phase = Phase::AwaitingWelcome;
    }

    async fn drive_sasl(&mut self, msg: &crate::Message<'_>) {
        // Server sends `AUTHENTICATE +` to ask for the payload chunk.
        if msg.is_command("AUTHENTICATE") {
            if msg.param(0) == Some("+") {
                if let Some(mech) = &self.config.sasl {
                    for line in sasl_authenticate_lines(mech) {
                        self.send(line).await;
                    }
                }
            }
            return;
        }

        // Numerics that resolve the SASL flow.
        let Command::Numeric(n) = msg.command else {
            return;
        };
        match n {
            903 => {
                info!("session: SASL succeeded");
                let _ = self
                    .events
                    .send(SessionEvent::SaslOutcome { succeeded: true })
                    .await;
                self.send("CAP END").await;
                self.phase = Phase::AwaitingWelcome;
            }
            // 902 ERR_NICKLOCKED, 904 ERR_SASLFAIL, 905 ERR_SASLTOOLONG,
            // 906 ERR_SASLABORTED, 907 ERR_SASLALREADY, 908 RPL_SASLMECHS.
            //
            // 908 is informational — server advertising mechanism list — and
            // not a terminal failure. Treat the rest as terminal: emit a
            // failed SaslOutcome and finish caps so the connection at least
            // makes it to RPL_WELCOME unauthenticated. Misconfigured
            // SASL shouldn't wedge the session.
            902 | 904 | 905 | 906 | 907 => {
                warn!(numeric = n, "session: SASL failed; continuing without auth");
                let _ = self
                    .events
                    .send(SessionEvent::SaslOutcome { succeeded: false })
                    .await;
                self.send("CAP END").await;
                self.phase = Phase::AwaitingWelcome;
            }
            _ => {}
        }
    }

    async fn apply_state_event(&mut self, evt: StateEvent) {
        match evt {
            StateEvent::Welcomed { nick } => {
                info!(nick = %nick, "session: registered");
                self.phase = Phase::Registered;
                self.ready.set(true);
                let _ = self
                    .events
                    .send(SessionEvent::Welcomed { nick: nick.clone() })
                    .await;
                for chan in &self.config.channels {
                    self.send(format!("JOIN {chan}")).await;
                }
            }
            StateEvent::Joined {
                channel,
                member,
                is_self,
            } => {
                let _ = self
                    .events
                    .send(SessionEvent::Joined {
                        channel,
                        nick: member.nick,
                        user: member.user,
                        host: member.host,
                        is_self,
                    })
                    .await;
            }
            StateEvent::Ping { token } => {
                self.send(format!("PONG :{token}")).await;
            }
            StateEvent::Privmsg { from, target, body } => {
                let _ = self
                    .events
                    .send(SessionEvent::Privmsg { from, target, body })
                    .await;
            }
            StateEvent::Notice { from, target, body } => {
                let _ = self
                    .events
                    .send(SessionEvent::Notice { from, target, body })
                    .await;
            }
            StateEvent::Parted { .. }
            | StateEvent::Kicked { .. }
            | StateEvent::NickChanged { .. }
            | StateEvent::Quit { .. }
            | StateEvent::TopicSet { .. }
            | StateEvent::ModeChanged { .. } => {
                // Tracked in ServerState; no SessionEvent surface yet.
            }
        }
    }

    async fn flush_mode_queue(&mut self) {
        for (_chan, line) in self.mode_queue.poll_due(true) {
            self.send(line).await;
        }
    }

    async fn send(&self, line: impl Into<String>) {
        let line = line.into();
        if let Err(err) = self.writer.send(line).await {
            warn!(error = %err, "session: writer send failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use crate::connection::{BackoffConfig, TlsMode, WriteRateConfig};

    fn config_for(addr: SocketAddr, sasl: Option<SaslMechanism>) -> SessionConfig {
        SessionConfig {
            connection: ConnectionConfig {
                addr,
                server_name: "test".into(),
                tls: TlsMode::Plain,
                backoff: BackoffConfig {
                    initial: Duration::from_millis(10),
                    max: Duration::from_millis(50),
                    multiplier: 2.0,
                },
                write_rate: WriteRateConfig {
                    burst_bytes: 8192,
                    refill_bps: 65_536,
                },
            },
            nick: "shade".into(),
            ident: "shade".into(),
            realname: "Shade Test".into(),
            desired_caps: vec!["sasl".into()],
            sasl,
            channels: vec!["#shade-test".into()],
        }
    }

    /// Spawn a fake IRC server that runs `script` once per accepted
    /// connection. The script gets a line-buffered reader and a writer
    /// half; it's responsible for exchanging lines to drive the session
    /// through whichever phases the test cares about.
    async fn fake_irc_server<F, Fut>(listener: TcpListener, script: F)
    where
        F: Fn(BufReader<tokio::net::tcp::OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf) -> Fut
            + Send
            + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        if let Ok((sock, _)) = listener.accept().await {
            let (read, write) = sock.into_split();
            let reader = BufReader::new(read);
            script(reader, write).await;
        }
    }

    async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Option<String> {
        let mut buf = String::new();
        match reader.read_line(&mut buf).await {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(buf.trim_end_matches(['\r', '\n']).to_string()),
        }
    }

    #[tokio::test]
    async fn end_to_end_no_sasl_reaches_welcome_and_joins() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(fake_irc_server(
            listener,
            |mut reader, mut write| async move {
                // Expect: CAP LS 302, NICK, USER
                let cap_ls = read_line(&mut reader).await.unwrap();
                assert!(cap_ls.starts_with("CAP LS"), "got: {cap_ls}");
                let nick = read_line(&mut reader).await.unwrap();
                assert!(nick.starts_with("NICK shade"), "got: {nick}");
                let user = read_line(&mut reader).await.unwrap();
                assert!(user.starts_with("USER shade"), "got: {user}");

                // Server has no overlapping caps → session sends CAP END.
                write
                    .write_all(b":server CAP * LS :server-time\r\n")
                    .await
                    .unwrap();
                let cap_end = read_line(&mut reader).await.unwrap();
                assert_eq!(cap_end, "CAP END");

                // Welcome.
                write
                    .write_all(b":server 001 shade :Welcome\r\n")
                    .await
                    .unwrap();

                // Expect JOIN.
                let join = read_line(&mut reader).await.unwrap();
                assert_eq!(join, "JOIN #shade-test");

                // Confirm the join from the server side.
                write
                    .write_all(b":shade!u@h JOIN #shade-test\r\n")
                    .await
                    .unwrap();

                // Hold open briefly so the client can deliver events.
                tokio::time::sleep(Duration::from_millis(50)).await;
            },
        ));

        let ready = ReadyHandle::new();
        let mut session = Session::spawn(config_for(addr, None), ready.clone());

        let mut got_welcome = false;
        let mut got_join = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            let next = tokio::time::timeout(Duration::from_millis(200), session.next_event()).await;
            let Ok(Some(evt)) = next else {
                continue;
            };
            match evt {
                SessionEvent::Welcomed { nick } => {
                    assert_eq!(nick, "shade");
                    got_welcome = true;
                }
                SessionEvent::Joined {
                    channel, is_self, ..
                } if is_self => {
                    assert_eq!(channel, "#shade-test");
                    got_join = true;
                    break;
                }
                _ => {}
            }
        }

        assert!(got_welcome, "never received Welcomed event");
        assert!(got_join, "never received self-Joined event");
        assert!(
            ready.is_ready(),
            "ReadyHandle should be set after RPL_WELCOME"
        );

        session.shutdown().await;
        let _ = server.await;
    }

    #[tokio::test]
    async fn end_to_end_sasl_plain_completes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(fake_irc_server(
            listener,
            |mut reader, mut write| async move {
                // Boot lines.
                let _ = read_line(&mut reader).await; // CAP LS
                let _ = read_line(&mut reader).await; // NICK
                let _ = read_line(&mut reader).await; // USER

                // Advertise sasl; expect CAP REQ :sasl.
                write
                    .write_all(b":server CAP * LS :sasl\r\n")
                    .await
                    .unwrap();
                let req = read_line(&mut reader).await.unwrap();
                assert_eq!(req, "CAP REQ :sasl");

                // Ack sasl; expect AUTHENTICATE PLAIN.
                write
                    .write_all(b":server CAP * ACK :sasl\r\n")
                    .await
                    .unwrap();
                let auth = read_line(&mut reader).await.unwrap();
                assert_eq!(auth, "AUTHENTICATE PLAIN");

                // Server responds with AUTHENTICATE +; expect the payload chunk.
                write.write_all(b"AUTHENTICATE +\r\n").await.unwrap();
                let payload = read_line(&mut reader).await.unwrap();
                assert!(payload.starts_with("AUTHENTICATE "));

                // 903 success → expect CAP END.
                write
                    .write_all(b":server 903 shade :SASL successful\r\n")
                    .await
                    .unwrap();
                let cap_end = read_line(&mut reader).await.unwrap();
                assert_eq!(cap_end, "CAP END");

                // Welcome and let the client try to join.
                write
                    .write_all(b":server 001 shade :Welcome\r\n")
                    .await
                    .unwrap();
                let _ = read_line(&mut reader).await; // JOIN
                tokio::time::sleep(Duration::from_millis(20)).await;
            },
        ));

        let mech = SaslMechanism::Plain {
            authzid: String::new(),
            username: "shade".into(),
            password: "hunter2".into(),
        };
        let ready = ReadyHandle::new();
        let mut session = Session::spawn(config_for(addr, Some(mech)), ready.clone());

        let mut got_sasl_ok = false;
        let mut got_welcome = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            let next = tokio::time::timeout(Duration::from_millis(200), session.next_event()).await;
            let Ok(Some(evt)) = next else {
                continue;
            };
            match evt {
                SessionEvent::SaslOutcome { succeeded: true } => got_sasl_ok = true,
                SessionEvent::Welcomed { .. } => {
                    got_welcome = true;
                    break;
                }
                _ => {}
            }
        }

        assert!(got_sasl_ok, "never received SaslOutcome{{succeeded: true}}");
        assert!(got_welcome, "never received Welcomed event");

        session.shutdown().await;
        let _ = server.await;
    }

    #[tokio::test]
    async fn ping_is_answered_with_pong() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(fake_irc_server(
            listener,
            |mut reader, mut write| async move {
                let _ = read_line(&mut reader).await; // CAP LS
                let _ = read_line(&mut reader).await; // NICK
                let _ = read_line(&mut reader).await; // USER

                write.write_all(b":server CAP * LS :\r\n").await.unwrap();
                let _ = read_line(&mut reader).await; // CAP END

                // Send PING before welcome — handler runs from ServerState
                // regardless of phase.
                write.write_all(b"PING :wakeywakey\r\n").await.unwrap();
                let pong = read_line(&mut reader).await.unwrap();
                assert_eq!(pong, "PONG :wakeywakey");

                tokio::time::sleep(Duration::from_millis(20)).await;
            },
        ));

        let ready = ReadyHandle::new();
        let session = Session::spawn(config_for(addr, None), ready);
        // The assertions live in the server task; just give it time.
        tokio::time::sleep(Duration::from_millis(300)).await;
        session.shutdown().await;
        let _ = server.await;
    }
}
