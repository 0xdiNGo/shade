//! Channel records.
//!
//! A [`Channel`] is the global handle for an IRC channel — name, ID,
//! creation timestamps. Mutable per-channel state (chanset flags, enforced
//! modes, saved topic) lives in [`ChannelSettings`]. The two were split so
//! a mesh-driven settings update doesn't touch the channel's identity row.

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::flags::FlagSet;
use crate::user::UserId;

/// Stable channel identifier (16-byte ULID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChannelId(pub Ulid);

impl ChannelId {
    #[must_use]
    pub fn new() -> Self {
        Self(Ulid::new())
    }

    #[must_use]
    pub fn as_bytes(self) -> [u8; 16] {
        self.0.to_bytes()
    }

    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Ulid::from_bytes(bytes))
    }
}

impl Default for ChannelId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// Persisted channel record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channel {
    pub id: ChannelId,
    /// IRC channel name including the `#` (or `&`) prefix. Stored
    /// case-insensitively in SQLite via `COLLATE NOCASE`.
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub origin_node: String,
}

/// Per-channel settings managed by Shade (chanset flags, enforced modes,
/// saved topic, key/limit protections).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSettings {
    pub channel_id: ChannelId,
    /// Channel-level chanset flags (`+a` autop, `+s` strict mask, etc.).
    /// The exact letter set is defined by Shade and intentionally trims
    /// Wraith's 25-toggle list down to the 12 we ship in MVP — see
    /// `docs/Improvements-Over-Wraith.md` for what we dropped and why.
    #[serde(default)]
    pub flags: FlagSet,
    /// Modes Shade will *enforce* by setting (`+ntC`, etc.). Set whenever
    /// they're missing from the live channel state.
    #[serde(default)]
    pub mode_pls: String,
    /// Modes Shade will *enforce* by removing.
    #[serde(default)]
    pub mode_mns: String,
    /// Enforced channel limit (`+l N`), or `None` for "don't manage".
    #[serde(default)]
    pub limit_prot: Option<i32>,
    /// Enforced channel key (`+k key`), or `None`.
    #[serde(default)]
    pub key_prot: Option<String>,
    /// Topic Shade will restore if it goes missing.
    #[serde(default)]
    pub topic_saved: Option<String>,
    pub updated_at: i64,
    pub origin_node: String,
}

/// User's per-channel flag set (the row that decides whether they get
/// auto-opped, kicked on join, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelUserFlags {
    pub channel_id: ChannelId,
    pub user_id: UserId,
    pub flags: FlagSet,
    pub updated_at: i64,
    pub origin_node: String,
}

/// Inputs to create a new channel. Server fills in the rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewChannel {
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_id_round_trips_through_bytes() {
        let id = ChannelId::new();
        let back = ChannelId::from_bytes(id.as_bytes());
        assert_eq!(id, back);
    }

    #[test]
    fn channel_settings_serde_round_trip() {
        let settings = ChannelSettings {
            channel_id: ChannelId::new(),
            flags: "+ax".parse().unwrap(),
            mode_pls: "ntC".into(),
            mode_mns: String::new(),
            limit_prot: Some(50),
            key_prot: None,
            topic_saved: Some("Hello".into()),
            updated_at: 1_700_000_000_000,
            origin_node: "node-a".into(),
        };
        let j = serde_json::to_string(&settings).unwrap();
        let back: ChannelSettings = serde_json::from_str(&j).unwrap();
        assert_eq!(settings, back);
    }
}
