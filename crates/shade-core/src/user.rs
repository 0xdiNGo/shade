//! User records.
//!
//! A [`User`] is one entry in the global address book: a stable handle plus
//! the network-wide flag set. Per-channel privileges live in
//! [`crate::ChannelUserFlags`] keyed by `(channel_id, user_id)`.

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::FlagSet;

/// Stable user identifier (16-byte ULID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub Ulid);

impl UserId {
    /// Generate a fresh `UserId` (monotonic ULID).
    #[must_use]
    pub fn new() -> Self {
        Self(Ulid::new())
    }

    /// Convert to a 16-byte big-endian array, suitable for storing as a
    /// SQLite `BLOB` primary key.
    #[must_use]
    pub fn as_bytes(self) -> [u8; 16] {
        self.0.to_bytes()
    }

    /// Reconstruct a `UserId` from a 16-byte big-endian representation.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Ulid::from_bytes(bytes))
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// Persisted user record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    /// Case-insensitive unique handle the operator uses to refer to this user.
    pub handle: String,
    /// Bcrypt/argon2 hash of an admin password, if any. `None` when the
    /// user authenticates only via mTLS or hostmask passive identification.
    /// Wraith stored crypted passwords too (`MD5SHA1` or `BLOWFISH`); we
    /// dropped both. Only modern KDFs are accepted in v0.
    pub password_hash: Option<String>,
    /// Bot accounts: mesh peers identified by handle, not interactive users.
    pub is_bot: bool,
    /// Network-wide flag set (e.g. `+a` admin, `+n` owner). Per-channel
    /// flags live in [`crate::ChannelUserFlags`].
    pub global_flags: FlagSet,
    /// Optional free-form comment shown alongside the user in admin tools.
    pub comment: Option<String>,
    /// Hostmasks attached to this user for passive identification (NOT for
    /// permission grants — see Architecture.md § Authentication).
    pub hosts: Vec<String>,
    /// Unix milliseconds.
    pub created_at: i64,
    /// Unix milliseconds.
    pub updated_at: i64,
    /// Unix milliseconds; `None` if the user has never been seen on IRC.
    pub last_seen_at: Option<i64>,
    /// Stable identifier of the node that last wrote this row. Used by
    /// last-write-wins gossip (M4) to break ties.
    pub origin_node: String,
}

/// Inputs required to create a new user. Excludes server-assigned fields
/// (id, timestamps, origin_node).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewUser {
    pub handle: String,
    #[serde(default)]
    pub password_hash: Option<String>,
    #[serde(default)]
    pub is_bot: bool,
    #[serde(default)]
    pub global_flags: FlagSet,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_round_trips_through_bytes() {
        let id = UserId::new();
        let restored = UserId::from_bytes(id.as_bytes());
        assert_eq!(id, restored);
    }

    #[test]
    fn user_id_serializes_as_string() {
        let id = UserId::from_bytes([0; 16]);
        let json = serde_json::to_string(&id).unwrap();
        // Ulid::Display is 26 characters of Crockford base32.
        assert_eq!(json.len(), 28); // 26 + two quotes
    }

    #[test]
    fn new_user_defaults_omit_optional_fields() {
        let nu: NewUser = serde_json::from_str(r#"{"handle":"alice"}"#).unwrap();
        assert_eq!(nu.handle, "alice");
        assert!(!nu.is_bot);
        assert_eq!(nu.global_flags, FlagSet::NONE);
        assert!(nu.hosts.is_empty());
    }
}
