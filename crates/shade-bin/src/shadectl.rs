//! `shadectl` operator CLI: HTTP client for the `/v1` admin API.
//!
//! Synchronous (`ureq`) — every subcommand is a short-lived HTTP request.
//! No tokio runtime, no connection pool. The `ClientArgs` flags
//! (`--base`, `--actor`, `--cert`, `--key`, `--ca-bundle`, `--pretty`)
//! are shared across every subcommand via `#[command(flatten)]` in
//! `cli.rs`.
//!
//! When `--cert` is set, ureq's rustls config presents the cert to the
//! daemon's mTLS admin listener, the daemon derives the audit actor
//! from the verified cert CN, and the URL scheme defaults to `https`.

use std::fmt::Write;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore};
use serde_json::json;

use crate::cli::{ChannelsCommand, ChansetCommand, ClientArgs, MaskCommand, UsersCommand};
use crate::config::Config;

// ----- HTTP client -------------------------------------------------------

struct ApiClient {
    base: String,
    actor: String,
    pretty: bool,
    agent: ureq::Agent,
}

impl ApiClient {
    fn from_args(config_path: &Path, args: &ClientArgs) -> Result<Self> {
        let cfg = Config::load(config_path)
            .with_context(|| format!("loading {}", config_path.display()))?;
        let tls_enabled = args.cert.is_some();
        let base = if let Some(b) = &args.base {
            b.clone()
        } else {
            let listen = cfg.admin.listen;
            let host = match listen.ip() {
                std::net::IpAddr::V4(ip) if ip.is_unspecified() => "127.0.0.1".to_owned(),
                other => other.to_string(),
            };
            let scheme = if tls_enabled { "https" } else { "http" };
            format!("{scheme}://{host}:{}", listen.port())
        };
        let actor = args
            .actor
            .clone()
            .unwrap_or_else(|| format!("cli:{}", whoami_or_unknown()));
        let agent = build_agent(args, &cfg)?;
        Ok(Self {
            base,
            actor,
            pretty: args.pretty,
            agent,
        })
    }

    fn request(&self, method: &str, path: &str) -> ureq::Request {
        let url = format!("{}{path}", self.base);
        self.agent.request(method, &url).set("X-Actor", &self.actor)
    }

    fn run_json(&self, req: ureq::Request, body: Option<&serde_json::Value>) -> Result<()> {
        let resp = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        match resp {
            Ok(r) => {
                let status = r.status();
                let text = r.into_string().unwrap_or_default();
                if text.is_empty() {
                    println!("{{\"status\":{status}}}");
                    return Ok(());
                }
                let value: serde_json::Value =
                    serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
                self.print(&value);
                Ok(())
            }
            Err(ureq::Error::Status(code, response)) => {
                let body = response.into_string().unwrap_or_default();
                anyhow::bail!("HTTP {code}: {body}")
            }
            Err(e) => anyhow::bail!("HTTP error: {e}"),
        }
    }

    fn print(&self, value: &serde_json::Value) {
        let s = if self.pretty {
            serde_json::to_string_pretty(value).unwrap_or_default()
        } else {
            serde_json::to_string(value).unwrap_or_default()
        };
        println!("{s}");
    }
}

fn whoami_or_unknown() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

/// Build the ureq Agent. When `--cert` is supplied, configures rustls
/// with the operator's client certificate + private key and the
/// CA bundle that signs the daemon's admin server cert; otherwise
/// returns a plain Agent that can only speak HTTP.
fn build_agent(args: &ClientArgs, cfg: &Config) -> Result<ureq::Agent> {
    let Some(cert_path) = &args.cert else {
        if args.key.is_some() {
            return Err(anyhow!("--key requires --cert"));
        }
        return Ok(ureq::AgentBuilder::new().build());
    };
    let key_path = args
        .key
        .as_ref()
        .ok_or_else(|| anyhow!("--cert requires --key"))?;
    let ca_path = args
        .ca_bundle
        .as_deref()
        .unwrap_or(cfg.node.tls.ca_bundle.as_path());

    let ca_certs = read_pem_certs(ca_path)?;
    let cert_chain = read_pem_certs(cert_path)?;
    let key = read_pem_key(key_path)?;

    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots
            .add(cert)
            .map_err(|e| anyhow!("adding CA to root store: {e}"))?;
    }
    let tls = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .map_err(|e| anyhow!("building rustls client config: {e}"))?;

    Ok(ureq::AgentBuilder::new().tls_config(Arc::new(tls)).build())
}

fn read_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let pem =
        fs::read_to_string(path).with_context(|| format!("reading PEM at {}", path.display()))?;
    let mut out = Vec::new();
    for block in pem::parse_many(pem.as_bytes())
        .with_context(|| format!("parsing PEM at {}", path.display()))?
    {
        if block.tag().eq_ignore_ascii_case("CERTIFICATE") {
            out.push(CertificateDer::from(block.contents().to_vec()));
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

fn read_pem_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
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

fn percent_encode(s: &str) -> String {
    // Minimal URL-path encoder: encode characters that are reserved in a
    // path segment per RFC 3986. Channel names start with `#` which must
    // be encoded as `%23`. Handles are alphanumerics so usually pass
    // through, but we still sanitize.
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

// ----- subcommand dispatchers --------------------------------------------

pub fn users(cmd: &UsersCommand, config: &Path) -> Result<()> {
    match cmd {
        UsersCommand::List { client } => {
            let c = ApiClient::from_args(config, client)?;
            c.run_json(c.request("GET", "/v1/users"), None)
        }
        UsersCommand::Show { handle, client } => {
            let c = ApiClient::from_args(config, client)?;
            let path = format!("/v1/users/{}", percent_encode(handle));
            c.run_json(c.request("GET", &path), None)
        }
        UsersCommand::Upsert {
            handle,
            flags,
            bot,
            comment,
            hosts,
            client,
        } => {
            let c = ApiClient::from_args(config, client)?;
            let mut body = json!({
                "handle": handle,
                "is_bot": bot,
                "hosts": hosts,
            });
            if let Some(f) = flags {
                body["global_flags"] = json!(f);
            }
            if let Some(cm) = comment {
                body["comment"] = json!(cm);
            }
            c.run_json(c.request("POST", "/v1/users"), Some(&body))
        }
        UsersCommand::Delete { handle, client } => {
            let c = ApiClient::from_args(config, client)?;
            let path = format!("/v1/users/{}", percent_encode(handle));
            c.run_json(c.request("DELETE", &path), None)
        }
        UsersCommand::Chattr {
            handle,
            diff,
            client,
        } => {
            let c = ApiClient::from_args(config, client)?;
            let path = format!("/v1/users/{}", percent_encode(handle));
            let body = json!({ "flags_diff": diff });
            c.run_json(c.request("PATCH", &path), Some(&body))
        }
    }
}

pub fn channels(cmd: &ChannelsCommand, config: &Path) -> Result<()> {
    match cmd {
        ChannelsCommand::List { client } => {
            let c = ApiClient::from_args(config, client)?;
            c.run_json(c.request("GET", "/v1/channels"), None)
        }
        ChannelsCommand::Show { name, client } => {
            let c = ApiClient::from_args(config, client)?;
            let path = format!("/v1/channels/{}", percent_encode(name));
            c.run_json(c.request("GET", &path), None)
        }
        ChannelsCommand::Upsert { name, client } => {
            let c = ApiClient::from_args(config, client)?;
            let body = json!({ "name": name });
            c.run_json(c.request("POST", "/v1/channels"), Some(&body))
        }
        ChannelsCommand::Delete { name, client } => {
            let c = ApiClient::from_args(config, client)?;
            let path = format!("/v1/channels/{}", percent_encode(name));
            c.run_json(c.request("DELETE", &path), None)
        }
    }
}

pub fn chanset(cmd: &ChansetCommand, config: &Path) -> Result<()> {
    match cmd {
        ChansetCommand::Get { name, client } => {
            let c = ApiClient::from_args(config, client)?;
            let path = format!("/v1/channels/{}/settings", percent_encode(name));
            c.run_json(c.request("GET", &path), None)
        }
        ChansetCommand::Put {
            name,
            flags,
            mode_pls,
            mode_mns,
            limit,
            no_limit,
            key,
            no_key,
            topic,
            no_topic,
            client,
        } => {
            let c = ApiClient::from_args(config, client)?;
            let mut body = json!({});
            if let Some(f) = flags {
                body["flags"] = json!(f);
            }
            if let Some(m) = mode_pls {
                body["mode_pls"] = json!(m);
            }
            if let Some(m) = mode_mns {
                body["mode_mns"] = json!(m);
            }
            if let Some(l) = limit {
                body["limit_prot"] = json!(l);
            } else if *no_limit {
                body["limit_prot"] = serde_json::Value::Null;
            }
            if let Some(k) = key {
                body["key_prot"] = json!(k);
            } else if *no_key {
                body["key_prot"] = serde_json::Value::Null;
            }
            if let Some(t) = topic {
                body["topic_saved"] = json!(t);
            } else if *no_topic {
                body["topic_saved"] = serde_json::Value::Null;
            }
            let path = format!("/v1/channels/{}/settings", percent_encode(name));
            c.run_json(c.request("PUT", &path), Some(&body))
        }
    }
}

pub fn chattr_channel(
    handle: &str,
    channel: &str,
    diff: &str,
    client_args: &ClientArgs,
    config: &Path,
) -> Result<()> {
    let c = ApiClient::from_args(config, client_args)?;
    let path = format!(
        "/v1/channels/{}/users/{}",
        percent_encode(channel),
        percent_encode(handle)
    );
    let body = json!({ "flags_diff": diff });
    c.run_json(c.request("PUT", &path), Some(&body))
}

pub fn mask(cmd: &MaskCommand, config: &Path) -> Result<()> {
    match cmd {
        MaskCommand::List {
            channel,
            kind,
            client,
        } => {
            let c = ApiClient::from_args(config, client)?;
            let path = format!(
                "/v1/channels/{}/masks?kind={}",
                percent_encode(channel),
                percent_encode(kind)
            );
            c.run_json(c.request("GET", &path), None)
        }
        MaskCommand::Add {
            channel,
            mask,
            kind,
            reason,
            expires_at,
            sticky,
            client,
        } => {
            let c = ApiClient::from_args(config, client)?;
            let mut body = json!({
                "kind": kind,
                "mask": mask,
                "sticky": sticky,
            });
            if let Some(r) = reason {
                body["reason"] = json!(r);
            }
            if let Some(e) = expires_at {
                body["expires_at"] = json!(e);
            }
            let path = format!("/v1/channels/{}/masks", percent_encode(channel));
            c.run_json(c.request("POST", &path), Some(&body))
        }
        MaskCommand::Remove { id, client } => {
            let c = ApiClient::from_args(config, client)?;
            let path = format!("/v1/masks/{}", percent_encode(id));
            c.run_json(c.request("DELETE", &path), None)
        }
    }
}

pub fn audit(
    limit: usize,
    actor: Option<&str>,
    client_args: &ClientArgs,
    config: &Path,
) -> Result<()> {
    let c = ApiClient::from_args(config, client_args)?;
    let mut path = format!("/v1/audit?limit={limit}");
    if let Some(a) = actor {
        let _ = write!(path, "&actor={}", percent_encode(a));
    }
    c.run_json(c.request("GET", &path), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_handles_channel_names_and_passthrough_alphanums() {
        assert_eq!(percent_encode("#shade-test"), "%23shade-test");
        assert_eq!(percent_encode("alice"), "alice");
        assert_eq!(percent_encode("alice.bob_42"), "alice.bob_42");
        assert_eq!(percent_encode("user!u@h"), "user%21u%40h");
    }

    #[test]
    fn percent_encode_uppercases_hex_digits() {
        // `:` is 0x3A → "%3A" not "%3a".
        assert_eq!(percent_encode("a:b"), "a%3Ab");
    }
}
