use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use figment::providers::{Env, Format, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};

/// Top-level Shade configuration.
///
/// Loaded from a TOML file with optional `SHADE_*` environment variable
/// overlays (using `__` as the section separator, e.g.
/// `SHADE_NODE__ID=shade-iad-01`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub node: NodeConfig,
    pub mesh: MeshConfig,
    pub network: NetworkConfig,
    pub admin: AdminConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeConfig {
    /// Globally unique, stable node identifier.
    pub id: String,
    /// Directory for SQLite, audit logs, and other persistent state.
    pub data_dir: PathBuf,
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    /// PEM bundle of trusted CAs for peer verification.
    pub ca_bundle: PathBuf,
    /// PEM-encoded node certificate.
    pub cert: PathBuf,
    /// PEM-encoded node private key.
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MeshConfig {
    /// Address to listen on for inbound peer connections.
    pub listen: SocketAddr,
    /// Static list of peer endpoints to dial.
    #[serde(default)]
    pub peers: Vec<MeshPeer>,
    /// Environment variable holding the mesh pre-shared key (used as the
    /// IKM for cookie-op key derivation).
    pub psk_env: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MeshPeer {
    pub node_id: String,
    pub endpoint: SocketAddr,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    /// Human-readable network name (informational).
    pub name: String,
    /// Server endpoints to dial, in `host:port` form. Tried in order with
    /// failover; rotation comes in v0.2.
    pub servers: Vec<String>,
    pub nick: String,
    pub ident: String,
    pub realname: String,
    /// Whether to use TLS when connecting to the IRC network.
    #[serde(default = "default_true")]
    pub tls: bool,
    /// SASL mechanism + credentials. `None` disables SASL.
    pub sasl: Option<SaslConfig>,
    /// IRCv3 capabilities to request during cap negotiation.
    #[serde(default)]
    pub caps: Vec<String>,
    /// Channels to JOIN once registration is complete.
    #[serde(default)]
    pub channels: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "mechanism", rename_all = "lowercase")]
pub enum SaslConfig {
    /// SASL PLAIN with explicit credentials. The password lives in an env var
    /// to keep it out of the config file.
    Plain {
        username: String,
        password_env: String,
    },
    /// SASL EXTERNAL using the same client cert as mesh authentication.
    External,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminConfig {
    /// Address for the HTTP+JSON admin API listener.
    pub listen: SocketAddr,
    /// Whether to require an mTLS client certificate. Strongly recommended.
    #[serde(default = "default_true")]
    pub require_mtls: bool,
    /// PEM bundle of CAs trusted to issue admin client certificates.
    pub client_ca: PathBuf,
    /// PEM-encoded server certificate presented to admin clients. Optional;
    /// when absent the daemon reuses the node's mesh certificate at
    /// `node.tls.cert`.
    #[serde(default)]
    pub server_cert: Option<PathBuf>,
    /// PEM-encoded server private key. Optional; defaults to `node.tls.key`
    /// when `server_cert` is also absent.
    #[serde(default)]
    pub server_key: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// `tracing` `EnvFilter` directive (e.g. `info`, `shade=debug,warn`).
    #[serde(default = "default_log_level")]
    pub level: String,
    /// `json` for ndjson to stdout, `text` for human-readable output.
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Address for the Prometheus `/metrics` listener.
    pub listen: SocketAddr,
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_owned()
}

fn default_log_format() -> String {
    "json".to_owned()
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to load config from {path}: {source}")]
    Figment {
        path: PathBuf,
        #[source]
        source: Box<figment::Error>,
    },
}

impl Config {
    /// Load configuration from a TOML file, layering `SHADE_*` environment
    /// variables on top.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Figment::new()
            .merge(Toml::file(path))
            .merge(Env::prefixed("SHADE_").split("__"))
            .extract()
            .map_err(|err| ConfigError::Figment {
                path: path.to_path_buf(),
                source: Box::new(err),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
[node]
id        = "shade-iad-01"
data_dir  = "/var/lib/shade"

[node.tls]
ca_bundle = "/etc/shade/pki/botnet-ca.pem"
cert      = "/etc/shade/pki/node.pem"
key       = "/etc/shade/pki/node.key"

[mesh]
listen    = "0.0.0.0:7331"
psk_env   = "SHADE_MESH_PSK"
peers = [
  { node_id = "shade-ord-01", endpoint = "10.0.1.12:7331" },
  { node_id = "shade-fra-01", endpoint = "10.0.2.12:7331" },
]

[network]
name      = "libera"
servers   = ["irc.libera.chat:6697"]
nick      = "shade"
ident     = "shade"
realname  = "Shade IRC Bot"
tls       = true
caps      = ["sasl", "server-time"]
sasl      = { mechanism = "external" }

[admin]
listen      = "0.0.0.0:8443"
client_ca   = "/etc/shade/pki/admin-ca.pem"

[metrics]
listen      = "127.0.0.1:9090"
"#;

    fn write_temp_config(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("create tempfile");
        file.write_all(contents.as_bytes()).expect("write tempfile");
        file
    }

    #[test]
    fn parses_minimal_full_config() {
        let file = write_temp_config(SAMPLE_TOML);
        let cfg = Config::load(file.path()).expect("config loads");

        assert_eq!(cfg.node.id, "shade-iad-01");
        assert_eq!(cfg.node.data_dir, Path::new("/var/lib/shade"));
        assert_eq!(cfg.mesh.peers.len(), 2);
        assert_eq!(cfg.mesh.peers[0].node_id, "shade-ord-01");
        assert_eq!(cfg.network.servers, vec!["irc.libera.chat:6697"]);
        assert!(matches!(cfg.network.sasl, Some(SaslConfig::External)));
        assert!(cfg.admin.require_mtls);
        assert_eq!(cfg.logging.level, "info");
        assert_eq!(cfg.logging.format, "json");
    }

    #[test]
    fn missing_required_field_fails() {
        let bad = r#"
[node]
id = "shade-iad-01"
# data_dir intentionally omitted

[node.tls]
ca_bundle = "/x/ca.pem"
cert      = "/x/c.pem"
key       = "/x/k.pem"

[mesh]
listen  = "0.0.0.0:7331"
psk_env = "SHADE_MESH_PSK"

[network]
name     = "libera"
servers  = ["irc.libera.chat:6697"]
nick     = "shade"
ident    = "shade"
realname = "Shade IRC Bot"

[admin]
listen    = "0.0.0.0:8443"
client_ca = "/x/admin.pem"

[metrics]
listen = "127.0.0.1:9090"
"#;
        let file = write_temp_config(bad);
        let err = Config::load(file.path()).expect_err("should fail without data_dir");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("data_dir"),
            "error should mention missing field, got: {rendered}"
        );
    }
}
