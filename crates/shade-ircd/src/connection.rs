//! IRC connection runner: TLS dial, line framing, rate-limited writes,
//! and automatic reconnect with exponential backoff.
//!
//! Spawn a [`Connection`] from a [`ConnectionConfig`]. The runner task
//! maintains a single TLS (or plaintext) session, emits high-level
//! [`ConnectionEvent`]s on a receiver channel, and accepts outbound lines
//! through a [`Writer`] handle. On disconnect it backs off and retries
//! forever, until the [`Writer`] (and therefore the runner) is dropped.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

use crate::rate_limit::RateLimiter;

/// Configuration for a Shade IRC connection.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Server `host:port` to dial.
    pub addr: SocketAddr,
    /// Server name used for TLS SNI and certificate verification.
    pub server_name: String,
    /// TLS posture.
    pub tls: TlsMode,
    /// Backoff schedule between reconnect attempts.
    pub backoff: BackoffConfig,
    /// Rate limiter for outbound bytes.
    pub write_rate: WriteRateConfig,
}

/// Whether the connection is wrapped in TLS, and if so what extra trust
/// anchors are pinned in addition to the bundled webpki roots.
#[derive(Debug, Clone)]
pub enum TlsMode {
    /// Plain TCP, no TLS. Intended for tests against a local IRCD over
    /// a loopback socket. **Insecure for any real network.**
    Plain,
    /// TLS with webpki-roots trust anchors plus any caller-provided
    /// additional roots (e.g. an internal CA for a private network).
    Tls {
        additional_roots: Vec<CertificateDer<'static>>,
    },
}

/// Exponential backoff schedule between reconnects.
#[derive(Debug, Clone)]
pub struct BackoffConfig {
    pub initial: Duration,
    pub max: Duration,
    pub multiplier: f64,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(60),
            multiplier: 2.0,
        }
    }
}

/// Outbound write rate. Defaults approximate the IRC server flood limit
/// of ~512 bytes / 2 s, with a 1 KiB burst.
#[derive(Debug, Clone)]
pub struct WriteRateConfig {
    pub burst_bytes: u64,
    pub refill_bps: u64,
}

impl Default for WriteRateConfig {
    fn default() -> Self {
        Self {
            burst_bytes: 1024,
            refill_bps: 256,
        }
    }
}

/// Events emitted by the connection runner.
#[derive(Debug)]
pub enum ConnectionEvent {
    /// Connected (TCP + TLS handshake completed). Subsequent lines are
    /// the server's initial banner, MOTD, etc.
    Connected,
    /// One IRC line received (CRLF stripped).
    Line(String),
    /// Active session ended; the runner will reconnect after `delay`.
    Disconnected { reason: String, delay: Duration },
}

/// Cloneable handle for sending outbound lines. A line is enqueued for
/// the runner; the runner appends `\r\n` and respects the configured
/// rate limit.
#[derive(Clone)]
pub struct Writer {
    tx: mpsc::Sender<String>,
}

impl Writer {
    /// Enqueue an outbound line. Returns `Err` if the connection runner
    /// has terminated (channel closed).
    pub async fn send(&self, line: impl Into<String>) -> Result<(), SendError> {
        self.tx
            .send(line.into())
            .await
            .map_err(|_| SendError::Closed)
    }

    /// Non-blocking variant. Returns `Err` if the channel is full or
    /// closed; useful for back-pressure-aware callers.
    pub fn try_send(&self, line: impl Into<String>) -> Result<(), SendError> {
        match self.tx.try_send(line.into()) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(SendError::Full),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(SendError::Closed),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("connection runner has terminated")]
    Closed,
    #[error("write queue is full")]
    Full,
}

/// A spawned connection runner. Holds the events receiver; the writer
/// handle is obtained via [`Connection::writer`]. Drop or call
/// [`Connection::shutdown`] to stop the runner.
pub struct Connection {
    events: mpsc::Receiver<ConnectionEvent>,
    write_tx: mpsc::Sender<String>,
    handle: JoinHandle<()>,
}

impl Connection {
    /// Spawn a connection runner. The runner reconnects forever (with
    /// exponential backoff) until the returned [`Connection`] is dropped.
    #[must_use]
    pub fn spawn(config: ConnectionConfig) -> Self {
        let (write_tx, write_rx) = mpsc::channel(64);
        let (event_tx, event_rx) = mpsc::channel(64);
        let handle = tokio::spawn(run(config, write_rx, event_tx));
        Self {
            events: event_rx,
            write_tx,
            handle,
        }
    }

    /// Get a cloneable handle for sending lines.
    #[must_use]
    pub fn writer(&self) -> Writer {
        Writer {
            tx: self.write_tx.clone(),
        }
    }

    /// Receive the next event. Returns `None` once the runner has fully
    /// terminated (only happens after the [`Connection`] is dropped or
    /// [`shutdown`] is called).
    pub async fn next_event(&mut self) -> Option<ConnectionEvent> {
        self.events.recv().await
    }

    /// Stop the runner and await its completion.
    pub async fn shutdown(self) {
        drop(self.write_tx);
        let _ = self.handle.await;
    }
}

async fn run(
    config: ConnectionConfig,
    mut write_rx: mpsc::Receiver<String>,
    event_tx: mpsc::Sender<ConnectionEvent>,
) {
    let mut delay = config.backoff.initial;
    loop {
        let outcome = match dial(&config).await {
            Ok(stream) => {
                if event_tx.send(ConnectionEvent::Connected).await.is_err() {
                    return;
                }
                delay = config.backoff.initial;
                drive_session(stream, &mut write_rx, &event_tx, &config.write_rate).await
            }
            Err(err) => format!("connect: {err}"),
        };

        if event_tx
            .send(ConnectionEvent::Disconnected {
                reason: outcome,
                delay,
            })
            .await
            .is_err()
        {
            return;
        }

        tokio::time::sleep(delay).await;
        delay = next_backoff(delay, &config.backoff);
    }
}

fn next_backoff(current: Duration, cfg: &BackoffConfig) -> Duration {
    let next_secs = current.as_secs_f64() * cfg.multiplier;
    Duration::from_secs_f64(next_secs.min(cfg.max.as_secs_f64()))
}

/// Boxed dyn stream so the read/write loops can be agnostic to whether
/// TLS is in use.
type IrcStream = Box<dyn IrcStreamTrait>;

trait IrcStreamTrait: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T> IrcStreamTrait for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

async fn dial(config: &ConnectionConfig) -> io::Result<IrcStream> {
    let tcp = TcpStream::connect(config.addr).await?;
    tcp.set_nodelay(true)?;
    info!(addr = %config.addr, "tcp connected");

    match &config.tls {
        TlsMode::Plain => Ok(Box::new(tcp)),
        TlsMode::Tls { additional_roots } => {
            let connector = build_tls_connector(additional_roots)?;
            let server_name = ServerName::try_from(config.server_name.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let tls = connector
                .connect(server_name, tcp)
                .await
                .map_err(io::Error::other)?;
            info!("tls handshake complete");
            Ok(Box::new(tls))
        }
    }
}

fn build_tls_connector(additional_roots: &[CertificateDer<'static>]) -> io::Result<TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in additional_roots {
        roots
            .add(cert.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

async fn drive_session(
    stream: IrcStream,
    write_rx: &mut mpsc::Receiver<String>,
    event_tx: &mpsc::Sender<ConnectionEvent>,
    rate: &WriteRateConfig,
) -> String {
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::with_capacity(8192, read_half);
    let mut limiter = RateLimiter::new(rate.burst_bytes, rate.refill_bps);

    let mut line_buf = String::new();
    loop {
        line_buf.clear();
        tokio::select! {
            biased;

            // Read one line from the server.
            read = reader.read_line(&mut line_buf) => {
                match read {
                    Ok(0) => return "eof from server".into(),
                    Ok(_) => {
                        let line = strip_eol(&line_buf).to_owned();
                        if event_tx.send(ConnectionEvent::Line(line)).await.is_err() {
                            return "event channel closed".into();
                        }
                    }
                    Err(e) => return format!("read: {e}"),
                }
            }

            // Write one queued line, respecting the rate limit.
            line = write_rx.recv() => {
                let Some(line) = line else {
                    // Caller dropped the writer side — graceful shutdown.
                    return "writer dropped".into();
                };
                let bytes = line.len() as u64 + 2; // CRLF
                limiter.wait_for(bytes).await;
                if let Err(e) = write_half.write_all(line.as_bytes()).await {
                    return format!("write line: {e}");
                }
                if let Err(e) = write_half.write_all(b"\r\n").await {
                    return format!("write eol: {e}");
                }
                if let Err(e) = write_half.flush().await {
                    return format!("flush: {e}");
                }
                debug!(bytes, "wrote line");
            }
        }
    }
}

fn strip_eol(s: &str) -> &str {
    if let Some(stripped) = s.strip_suffix("\r\n") {
        stripped
    } else if let Some(stripped) = s.strip_suffix('\n') {
        stripped
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_backoff_grows_then_caps() {
        let cfg = BackoffConfig {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(60),
            multiplier: 2.0,
        };
        let mut d = cfg.initial;
        for _ in 0..20 {
            d = next_backoff(d, &cfg);
        }
        assert_eq!(d, cfg.max);
    }

    #[test]
    fn next_backoff_doubles() {
        let cfg = BackoffConfig {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(60),
            multiplier: 2.0,
        };
        let d1 = cfg.initial;
        let d2 = next_backoff(d1, &cfg);
        let d3 = next_backoff(d2, &cfg);
        assert_eq!(d2, Duration::from_millis(200));
        assert_eq!(d3, Duration::from_millis(400));
    }

    #[test]
    fn strip_eol_handles_crlf_lf_and_neither() {
        assert_eq!(strip_eol("hello\r\n"), "hello");
        assert_eq!(strip_eol("hello\n"), "hello");
        assert_eq!(strip_eol("hello"), "hello");
    }

    #[tokio::test(start_paused = true)]
    async fn writer_send_returns_err_after_runner_drops_rx() {
        let (tx, rx) = mpsc::channel::<String>(4);
        let writer = Writer { tx };
        drop(rx);
        let err = writer.send("PING :foo").await.unwrap_err();
        assert!(matches!(err, SendError::Closed));
    }

    #[tokio::test(start_paused = true)]
    async fn writer_try_send_full_then_drains() {
        let (tx, mut rx) = mpsc::channel::<String>(2);
        let writer = Writer { tx };
        writer.try_send("a").unwrap();
        writer.try_send("b").unwrap();
        // queue is full
        let err = writer.try_send("c").unwrap_err();
        assert!(matches!(err, SendError::Full));
        // drain one and try again
        rx.recv().await.unwrap();
        writer.try_send("c").unwrap();
    }
}
