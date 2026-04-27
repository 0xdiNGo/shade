//! Bearer auth tokens for the admin API.
//!
//! Operators that don't carry an mTLS client cert can authenticate to
//! `/v1/...` with a bearer token issued by [`POST /v1/login`] (HTTP)
//! or via the in-channel `TOKEN` PRIVMSG flow.
//!
//! Tokens are 32 random bytes encoded as URL-safe base64 for the wire,
//! and stored at rest as their SHA-256 hash so that a stolen `auth_tokens`
//! row cannot be re-presented by an attacker (they'd have to find a
//! preimage). The wire form is shown to the operator exactly once when
//! the token is minted; from then on the daemon only ever sees the
//! hash.
//!
//! [`POST /v1/login`]: https://github.com/0xdiNGo/shade

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Default token lifetime (1 hour).
pub const DEFAULT_TTL_MS: i64 = 60 * 60 * 1_000;

/// Length of the random secret in bytes.
pub const TOKEN_BYTES: usize = 32;

/// A freshly-minted token in plaintext form. Show to the operator
/// exactly once and discard — only the [`AuthTokenHash`] is persisted.
#[derive(Clone)]
pub struct AuthToken {
    secret: [u8; TOKEN_BYTES],
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print secret bytes; the wire form is the only intended
        // exposure and even that is supposed to be one-shot.
        f.debug_struct("AuthToken").finish_non_exhaustive()
    }
}

impl AuthToken {
    /// Generate a fresh random token from the OS RNG.
    #[must_use]
    pub fn random() -> Self {
        let mut secret = [0u8; TOKEN_BYTES];
        OsRng.fill_bytes(&mut secret);
        Self { secret }
    }

    /// Encode for HTTP transport (`Authorization: Bearer …`). URL-safe
    /// base64, no padding. The exact same string is what the operator
    /// pastes into `shadectl --token`.
    #[must_use]
    pub fn to_wire(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.secret)
    }

    /// Parse a wire-form token. Rejects anything that doesn't decode to
    /// exactly [`TOKEN_BYTES`] bytes.
    pub fn from_wire(s: &str) -> Result<Self, AuthTokenError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s.trim())
            .map_err(|e| AuthTokenError::Decode(e.to_string()))?;
        let secret: [u8; TOKEN_BYTES] =
            bytes.try_into().map_err(|_| AuthTokenError::WrongLength)?;
        Ok(Self { secret })
    }

    /// SHA-256 of the secret. This is what we store at rest and what
    /// the lookup query hashes the presented bearer with before
    /// comparing.
    #[must_use]
    pub fn hash(&self) -> AuthTokenHash {
        let mut h = Sha256::new();
        h.update(self.secret);
        let arr: [u8; 32] = h.finalize().into();
        AuthTokenHash(arr)
    }
}

/// SHA-256 hash of an [`AuthToken`]'s secret. The persisted form.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthTokenHash(pub [u8; 32]);

impl std::fmt::Debug for AuthTokenHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hex prefix is fine — even a leak of the hash is non-trivially
        // exploitable (would need a preimage attack on SHA-256).
        let mut s = String::with_capacity(8);
        for b in &self.0[..4] {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        write!(f, "AuthTokenHash({s}…)")
    }
}

impl AuthTokenHash {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthTokenError {
    #[error("base64 decode: {0}")]
    Decode(String),
    #[error("decoded token has wrong length")]
    WrongLength,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_tokens_differ() {
        let a = AuthToken::random();
        let b = AuthToken::random();
        assert_ne!(a.secret, b.secret);
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn wire_round_trip_preserves_hash() {
        let t = AuthToken::random();
        let wire = t.to_wire();
        let parsed = AuthToken::from_wire(&wire).unwrap();
        assert_eq!(t.hash(), parsed.hash());
    }

    #[test]
    fn from_wire_rejects_wrong_length() {
        // 16-byte payload, not 32.
        let short = URL_SAFE_NO_PAD.encode([0u8; 16]);
        let err = AuthToken::from_wire(&short).unwrap_err();
        assert!(matches!(err, AuthTokenError::WrongLength));
    }

    #[test]
    fn from_wire_rejects_garbage() {
        let err = AuthToken::from_wire("!!! not base64").unwrap_err();
        assert!(matches!(err, AuthTokenError::Decode(_)));
    }
}
