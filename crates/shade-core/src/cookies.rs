//! Cross-bot op-replay protection.
//!
//! When one Shade node asks another to op a user (because it doesn't
//! hold `ROLE_OP` for that channel itself), the receiving node issues
//! the `MODE +o` along with a synthetic ban-mask carrying an HMAC-SHA256
//! cookie. Other Shade nodes observing the mode can verify the cookie
//! before treating the op as legitimate.
//!
//! Wraith does this with MD5 + a per-bot counter — see
//! `src/mod/irc.mod/irc.cc:488-552` (`makecookie`) and
//! `src/mod/irc.mod/irc.cc:559-638` (`checkcookie`). Their counter is
//! per-bot local state; netsplits cause counter divergence and operators
//! learn to ignore the bad-cookie alarms (see
//! `docs/Improvements-Over-Wraith.md` § 4 for the receipts).
//!
//! Shade replaces it with:
//!
//! * **HMAC-SHA256** over a typed payload, 128-bit truncated tag.
//! * **HKDF-SHA256** to derive a per-channel key from a shared mesh PSK.
//! * **Replay protection**: cookies carry a ULID `request_id` plus
//!   `ts_ms`. Verifiers reject `ts_ms` more than `MAX_FUTURE_SKEW_MS`
//!   in the future or `MAX_PAST_AGE_MS` in the past, and a
//!   `ReplayGuard` ring buffer dedupes recently-seen `request_id`s.

use std::collections::VecDeque;

use base64::Engine as _;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use ulid::Ulid;

use crate::time::now_ms;

/// HKDF-SHA256 salt — bumped on protocol-incompatible cookie changes.
pub const HKDF_SALT: &[u8] = b"shade/v1/cookie";

/// Tag length, in bytes (128 bits — full 256-bit HMAC truncated).
pub const TAG_LEN: usize = 16;

/// Reject cookies whose `ts_ms` is more than this far in the future.
pub const MAX_FUTURE_SKEW_MS: i64 = 5_000;

/// Reject cookies whose `ts_ms` is more than this far in the past.
pub const MAX_PAST_AGE_MS: i64 = 60_000;

/// Default ring-buffer size for the replay guard. 5 minutes worth of
/// request IDs at 1 op/sec leaves plenty of headroom.
pub const DEFAULT_REPLAY_GUARD_SIZE: usize = 4096;

/// Errors produced by cookie verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CookieError {
    /// The wire form was malformed (missing separator, base64 decode
    /// failure, payload too short).
    #[error("malformed cookie: {0}")]
    Malformed(String),
    /// HMAC tag did not match — either the key is wrong or the cookie
    /// was tampered with.
    #[error("invalid HMAC tag")]
    BadMac,
    /// `ts_ms` is too far in the future (clock skew) or too far in the
    /// past (replay window expired).
    #[error("timestamp out of bounds: {ts_ms} vs now {now_ms}")]
    TimestampOutOfBounds { ts_ms: i64, now_ms: i64 },
    /// `request_id` was seen recently — replay attempt.
    #[error("replay detected: request_id seen recently")]
    Replay,
}

/// One cookie payload. Serialized to a fixed binary layout (no msgpack)
/// so the wire form is short enough to embed in an IRC ban-mask.
///
/// Layout (76 bytes):
///
/// ```text
///   16  u128  request_id (ULID, big-endian)
///    8  i64   ts_ms (big-endian)
///    1  u8    requester_node_id length (≤ 32)
///   ≤32 utf8  requester_node_id bytes
///    1  u8    target_nick length (≤ 32)
///   ≤32 utf8  target_nick bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cookie {
    pub request_id: Ulid,
    pub ts_ms: i64,
    pub requester_node_id: String,
    pub target_nick: String,
}

impl Cookie {
    /// Build a fresh cookie for `(requester_node_id, target_nick)` and
    /// stamp `ts_ms = now_ms()`.
    #[must_use]
    pub fn new(requester_node_id: impl Into<String>, target_nick: impl Into<String>) -> Self {
        Self {
            request_id: Ulid::new(),
            ts_ms: now_ms(),
            requester_node_id: requester_node_id.into(),
            target_nick: target_nick.into(),
        }
    }

    /// Serialize the cookie to its fixed binary layout. Returns `None`
    /// if either string field exceeds 32 bytes (which a sanely-named
    /// node and IRC nick will never).
    #[must_use]
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let node = self.requester_node_id.as_bytes();
        let nick = self.target_nick.as_bytes();
        if node.len() > u8::MAX as usize || nick.len() > u8::MAX as usize {
            return None;
        }
        let mut buf = Vec::with_capacity(16 + 8 + 1 + node.len() + 1 + nick.len());
        buf.extend_from_slice(&self.request_id.to_bytes());
        buf.extend_from_slice(&self.ts_ms.to_be_bytes());
        buf.push(u8::try_from(node.len()).ok()?);
        buf.extend_from_slice(node);
        buf.push(u8::try_from(nick.len()).ok()?);
        buf.extend_from_slice(nick);
        Some(buf)
    }

    /// Reverse of [`Cookie::to_bytes`].
    pub fn from_bytes(buf: &[u8]) -> Result<Self, CookieError> {
        // 16 (ULID) + 8 (ts) + 1 (node-len byte) + 1 (nick-len byte)
        // — both length bytes can legitimately be zero, so this is the
        // smallest possible valid payload.
        if buf.len() < 16 + 8 + 1 + 1 {
            return Err(CookieError::Malformed("payload too short".into()));
        }
        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&buf[..16]);
        let request_id = Ulid::from_bytes(id_bytes);
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&buf[16..24]);
        let ts_ms = i64::from_be_bytes(ts_bytes);

        let node_len = buf[24] as usize;
        if buf.len() < 25 + node_len + 1 {
            return Err(CookieError::Malformed("truncated node id".into()));
        }
        let node_end = 25 + node_len;
        let requester_node_id = std::str::from_utf8(&buf[25..node_end])
            .map_err(|_| CookieError::Malformed("node id not utf-8".into()))?
            .to_owned();

        let nick_len = buf[node_end] as usize;
        if buf.len() < node_end + 1 + nick_len {
            return Err(CookieError::Malformed("truncated nick".into()));
        }
        let nick_start = node_end + 1;
        let nick_end = nick_start + nick_len;
        let target_nick = std::str::from_utf8(&buf[nick_start..nick_end])
            .map_err(|_| CookieError::Malformed("nick not utf-8".into()))?
            .to_owned();

        Ok(Self {
            request_id,
            ts_ms,
            requester_node_id,
            target_nick,
        })
    }
}

/// Derive a 32-byte channel-scoped key from the shared mesh PSK.
#[must_use]
pub fn derive_channel_key(mesh_psk: &[u8], channel_name: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), mesh_psk);
    let mut okm = [0u8; 32];
    hk.expand(channel_name.as_bytes(), &mut okm)
        .expect("HKDF expand of 32 bytes always succeeds");
    okm
}

/// Build the wire form of a cookie:
/// `base64-url(payload) + "." + base64-url(tag)`. The single `.` is the
/// separator the verifier splits on.
#[must_use]
pub fn make(cookie: &Cookie, channel_key: &[u8; 32]) -> Option<String> {
    let payload = cookie.to_bytes()?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(channel_key).ok()?;
    mac.update(&payload);
    let tag_full = mac.finalize().into_bytes();
    let tag = &tag_full[..TAG_LEN];

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    Some(format!("{}.{}", b64.encode(&payload), b64.encode(tag)))
}

/// Verify a wire-form cookie. Returns the parsed [`Cookie`] on success.
///
/// `replay_guard` is consulted (and updated on success) so the same
/// `request_id` can't be replayed.
pub fn verify(
    wire: &str,
    channel_key: &[u8; 32],
    replay_guard: &mut ReplayGuard,
) -> Result<Cookie, CookieError> {
    let (payload_b64, tag_b64) = wire
        .split_once('.')
        .ok_or_else(|| CookieError::Malformed("missing separator".into()))?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = b64
        .decode(payload_b64)
        .map_err(|_| CookieError::Malformed("payload base64".into()))?;
    let tag = b64
        .decode(tag_b64)
        .map_err(|_| CookieError::Malformed("tag base64".into()))?;
    if tag.len() != TAG_LEN {
        return Err(CookieError::Malformed("tag length".into()));
    }

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(channel_key)
        .map_err(|_| CookieError::Malformed("hmac init".into()))?;
    mac.update(&payload);
    let expected = mac.finalize().into_bytes();
    // Constant-time compare on the first TAG_LEN bytes.
    if !ct_eq(&expected[..TAG_LEN], &tag) {
        return Err(CookieError::BadMac);
    }

    let cookie = Cookie::from_bytes(&payload)?;
    let now = now_ms();
    if cookie.ts_ms - now > MAX_FUTURE_SKEW_MS || now - cookie.ts_ms > MAX_PAST_AGE_MS {
        return Err(CookieError::TimestampOutOfBounds {
            ts_ms: cookie.ts_ms,
            now_ms: now,
        });
    }
    if !replay_guard.observe(cookie.request_id) {
        return Err(CookieError::Replay);
    }
    Ok(cookie)
}

/// Constant-time equality compare. Returns `false` immediately on
/// length mismatch (length is not secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Ring-buffer replay guard. Holds the most-recent `capacity`
/// `request_id`s; on overflow the oldest is evicted. `observe` returns
/// `true` if the id is fresh, `false` if it was already in the ring.
#[derive(Debug)]
pub struct ReplayGuard {
    capacity: usize,
    seen: VecDeque<Ulid>,
}

impl ReplayGuard {
    /// Build a guard with [`DEFAULT_REPLAY_GUARD_SIZE`] entries.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_REPLAY_GUARD_SIZE)
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            seen: VecDeque::with_capacity(capacity),
        }
    }

    /// Record `id` as seen. Returns `false` if `id` was already in the
    /// ring, `true` if it was fresh (and thus inserted).
    pub fn observe(&mut self, id: Ulid) -> bool {
        if self.seen.iter().any(|seen| *seen == id) {
            return false;
        }
        if self.seen.len() == self.capacity && self.capacity > 0 {
            self.seen.pop_front();
        }
        self.seen.push_back(id);
        true
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_round_trips_through_bytes() {
        let c = Cookie::new("shade-iad-01", "alice");
        let bytes = c.to_bytes().unwrap();
        let back = Cookie::from_bytes(&bytes).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn cookie_to_bytes_rejects_oversize_strings() {
        let c = Cookie {
            request_id: Ulid::nil(),
            ts_ms: 0,
            requester_node_id: "x".repeat(256),
            target_nick: "y".into(),
        };
        assert!(c.to_bytes().is_none());
    }

    #[test]
    fn make_and_verify_round_trip_with_correct_key() {
        let psk = b"a-shared-mesh-psk-32-bytes-or-more.";
        let key = derive_channel_key(psk, "#shade-test");
        let cookie = Cookie::new("shade-iad-01", "alice");
        let wire = make(&cookie, &key).unwrap();
        let mut rg = ReplayGuard::new();
        let parsed = verify(&wire, &key, &mut rg).unwrap();
        assert_eq!(parsed.request_id, cookie.request_id);
        assert_eq!(parsed.target_nick, "alice");
    }

    #[test]
    fn verify_rejects_wrong_channel_key() {
        let psk = b"shared-psk-of-sufficient-length...";
        let key_a = derive_channel_key(psk, "#chan-a");
        let key_b = derive_channel_key(psk, "#chan-b");
        let wire = make(&Cookie::new("node", "alice"), &key_a).unwrap();
        let mut rg = ReplayGuard::new();
        let err = verify(&wire, &key_b, &mut rg).unwrap_err();
        assert_eq!(err, CookieError::BadMac);
    }

    #[test]
    fn verify_rejects_replay() {
        let psk = b"a-shared-mesh-psk-32-bytes-or-more.";
        let key = derive_channel_key(psk, "#shade-test");
        let wire = make(&Cookie::new("node", "alice"), &key).unwrap();
        let mut rg = ReplayGuard::new();
        verify(&wire, &key, &mut rg).expect("first time");
        let err = verify(&wire, &key, &mut rg).unwrap_err();
        assert_eq!(err, CookieError::Replay);
    }

    #[test]
    fn verify_rejects_stale_cookie() {
        let psk = b"a-shared-mesh-psk-32-bytes-or-more.";
        let key = derive_channel_key(psk, "#shade-test");
        let mut cookie = Cookie::new("node", "alice");
        cookie.ts_ms = now_ms() - MAX_PAST_AGE_MS - 1_000;
        let wire = make(&cookie, &key).unwrap();
        let mut rg = ReplayGuard::new();
        let err = verify(&wire, &key, &mut rg).unwrap_err();
        assert!(matches!(err, CookieError::TimestampOutOfBounds { .. }));
    }

    #[test]
    fn verify_rejects_future_cookie() {
        let psk = b"a-shared-mesh-psk-32-bytes-or-more.";
        let key = derive_channel_key(psk, "#shade-test");
        let mut cookie = Cookie::new("node", "alice");
        cookie.ts_ms = now_ms() + MAX_FUTURE_SKEW_MS + 1_000;
        let wire = make(&cookie, &key).unwrap();
        let mut rg = ReplayGuard::new();
        let err = verify(&wire, &key, &mut rg).unwrap_err();
        assert!(matches!(err, CookieError::TimestampOutOfBounds { .. }));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let psk = b"a-shared-mesh-psk-32-bytes-or-more.";
        let key = derive_channel_key(psk, "#shade-test");
        let wire = make(&Cookie::new("node", "alice"), &key).unwrap();
        // Flip a bit in the payload portion (before the `.`).
        let dot = wire.find('.').unwrap();
        let mut tampered: Vec<u8> = wire.as_bytes().to_vec();
        // 'a' XOR 1 = 'b' — keeps it base64-valid even after the flip
        // (URL_SAFE_NO_PAD allows letters); shouldn't validate anyway.
        tampered[dot - 1] ^= 0b0000_0001;
        let tampered = String::from_utf8(tampered).unwrap();
        let mut rg = ReplayGuard::new();
        let err = verify(&tampered, &key, &mut rg).unwrap_err();
        assert!(matches!(
            err,
            CookieError::BadMac | CookieError::Malformed(_)
        ));
    }

    #[test]
    fn verify_rejects_malformed_wire() {
        let key = [0u8; 32];
        let mut rg = ReplayGuard::new();
        for bad in ["", ".", "abc", "abc.def"] {
            assert!(verify(bad, &key, &mut rg).is_err(), "bad: {bad:?}");
        }
    }

    #[test]
    fn replay_guard_evicts_oldest_when_full() {
        let mut rg = ReplayGuard::with_capacity(2);
        let a = Ulid::new();
        let b = Ulid::new();
        let c = Ulid::new();
        assert!(rg.observe(a));
        assert!(rg.observe(b));
        assert!(rg.observe(c)); // evicts a
        assert!(rg.observe(a)); // a should be considered fresh again
    }

    #[test]
    fn derive_channel_key_is_per_channel() {
        let psk = b"some-mesh-psk";
        let a = derive_channel_key(psk, "#a");
        let b = derive_channel_key(psk, "#b");
        assert_ne!(a, b);
    }

    #[test]
    fn derive_channel_key_is_deterministic() {
        let psk = b"some-mesh-psk";
        assert_eq!(
            derive_channel_key(psk, "#shade-test"),
            derive_channel_key(psk, "#shade-test")
        );
    }
}
