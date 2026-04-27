//! SASL authentication encoding for IRCv3.
//!
//! Two mechanisms supported:
//!
//! - **PLAIN** — credentials over a TLS-protected channel. The shape is
//!   `authzid \0 username \0 password`, base64-encoded. Authzid is usually
//!   empty (the server uses `username` as the authentication identity).
//!
//! - **EXTERNAL** — uses the TLS client certificate the connection was
//!   established with. The payload is just the optional authzid (or `+` if
//!   none); the server already knows who you are from the cert.
//!
//! This module is pure: encoding only, no I/O. The session loop in
//! `session.rs` writes the resulting `AUTHENTICATE` line(s).
//!
//! The IRCv3 SASL spec splits payloads into 400-byte chunks ending with
//! `AUTHENTICATE +` if the encoded blob exceeds 400 bytes. For PLAIN with
//! reasonable credentials this never triggers; we still implement chunking
//! correctly via [`sasl_authenticate_lines`] to be safe.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

/// SASL mechanism + the data needed to compute its payload.
#[derive(Debug, Clone)]
pub enum SaslMechanism {
    /// `AUTHENTICATE PLAIN`; payload is `authzid \0 username \0 password`,
    /// base64-encoded.
    Plain {
        /// Authentication identity (usually empty).
        authzid: String,
        /// Username (account name).
        username: String,
        /// Cleartext password. Caller is expected to source this from a
        /// secret store / env var, not the config file.
        password: String,
    },
    /// `AUTHENTICATE EXTERNAL`; uses the TLS client cert. Payload is the
    /// optional authzid (empty by default → wire form is `+`).
    External {
        /// Optional authzid; empty means "use the cert's identity as-is".
        authzid: String,
    },
}

impl SaslMechanism {
    /// IRC `AUTHENTICATE` mechanism token (the first AUTHENTICATE line).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Plain { .. } => "PLAIN",
            Self::External { .. } => "EXTERNAL",
        }
    }

    /// The raw (un-base64'd) auth payload bytes.
    #[must_use]
    pub fn raw_payload(&self) -> Vec<u8> {
        match self {
            Self::Plain {
                authzid,
                username,
                password,
            } => {
                let mut buf =
                    Vec::with_capacity(authzid.len() + username.len() + password.len() + 2);
                buf.extend_from_slice(authzid.as_bytes());
                buf.push(0);
                buf.extend_from_slice(username.as_bytes());
                buf.push(0);
                buf.extend_from_slice(password.as_bytes());
                buf
            }
            Self::External { authzid } => authzid.as_bytes().to_vec(),
        }
    }
}

/// Build the `AUTHENTICATE <mechanism>` opening line.
#[must_use]
pub fn authenticate_start(mech: &SaslMechanism) -> String {
    format!("AUTHENTICATE {}", mech.name())
}

/// Build the sequence of `AUTHENTICATE <chunk>` lines that carry the
/// payload. Each chunk encodes ≤ 400 bytes of the raw payload (so the
/// base64 chunk is ≤ 540 bytes — well under the IRC 512-byte line limit
/// after the `AUTHENTICATE ` prefix). If the encoded payload's last chunk
/// is exactly 400 bytes, an extra `AUTHENTICATE +` terminator is appended
/// per the IRCv3 spec. An empty payload (e.g. EXTERNAL without authzid)
/// becomes a single `AUTHENTICATE +`.
#[must_use]
pub fn sasl_authenticate_lines(mech: &SaslMechanism) -> Vec<String> {
    let raw = mech.raw_payload();
    if raw.is_empty() {
        return vec!["AUTHENTICATE +".to_string()];
    }

    let mut lines = Vec::new();
    let chunk_size = 400;
    let mut last_chunk_len = 0;
    for chunk in raw.chunks(chunk_size) {
        last_chunk_len = chunk.len();
        let encoded = B64.encode(chunk);
        lines.push(format!("AUTHENTICATE {encoded}"));
    }

    // If the last raw chunk was exactly 400 bytes, send an empty
    // continuation marker so the server knows the payload ended cleanly.
    if last_chunk_len == chunk_size {
        lines.push("AUTHENTICATE +".to_string());
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_mechanism_name() {
        let m = SaslMechanism::Plain {
            authzid: String::new(),
            username: "shade".into(),
            password: "hunter2".into(),
        };
        assert_eq!(m.name(), "PLAIN");
    }

    #[test]
    fn plain_payload_layout() {
        let m = SaslMechanism::Plain {
            authzid: String::new(),
            username: "shade".into(),
            password: "hunter2".into(),
        };
        let raw = m.raw_payload();
        // empty + NUL + "shade" + NUL + "hunter2"
        assert_eq!(raw, b"\0shade\0hunter2");
    }

    #[test]
    fn plain_authenticate_lines_round_trip() {
        let m = SaslMechanism::Plain {
            authzid: String::new(),
            username: "shade".into(),
            password: "hunter2".into(),
        };
        let start = authenticate_start(&m);
        let body = sasl_authenticate_lines(&m);
        assert_eq!(start, "AUTHENTICATE PLAIN");
        assert_eq!(body.len(), 1);
        assert!(body[0].starts_with("AUTHENTICATE "));

        let encoded = body[0].trim_start_matches("AUTHENTICATE ");
        let decoded = B64.decode(encoded).unwrap();
        assert_eq!(decoded, b"\0shade\0hunter2");
    }

    #[test]
    fn external_with_no_authzid_is_plus() {
        let m = SaslMechanism::External {
            authzid: String::new(),
        };
        assert_eq!(authenticate_start(&m), "AUTHENTICATE EXTERNAL");
        assert_eq!(sasl_authenticate_lines(&m), vec!["AUTHENTICATE +"]);
    }

    #[test]
    fn external_with_authzid_is_encoded() {
        let m = SaslMechanism::External {
            authzid: "shadeops".into(),
        };
        let lines = sasl_authenticate_lines(&m);
        assert_eq!(lines.len(), 1);
        let encoded = lines[0].trim_start_matches("AUTHENTICATE ");
        assert_eq!(B64.decode(encoded).unwrap(), b"shadeops");
    }

    #[test]
    fn long_plain_payload_chunks_correctly() {
        // Pick a username that, with NULs and a short password, makes the
        // raw payload larger than 400 bytes.
        let username = "u".repeat(450);
        let m = SaslMechanism::Plain {
            authzid: String::new(),
            username: username.clone(),
            password: "p".into(),
        };
        let lines = sasl_authenticate_lines(&m);
        // Payload: 1 (authzid+NUL) + 450 (username) + 1 (NUL) + 1 (password) = 453 bytes
        // → two chunks: 400 + 53.
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("AUTHENTICATE "));
        assert!(lines[1].starts_with("AUTHENTICATE "));
    }

    #[test]
    fn payload_exactly_chunk_boundary_emits_terminator() {
        // 400-byte raw payload → one full chunk + AUTHENTICATE + terminator.
        let username = "u".repeat(398); // 0 + NUL + 398 + NUL = 400
        let m = SaslMechanism::Plain {
            authzid: String::new(),
            username,
            password: String::new(),
        };
        let lines = sasl_authenticate_lines(&m);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1], "AUTHENTICATE +");
    }
}
