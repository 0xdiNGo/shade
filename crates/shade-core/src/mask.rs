//! Hostmask records: bans, exempts, invites.
//!
//! The same row shape covers all three list types; [`MaskKind`] discriminates.
//! Channel-scoped masks set `channel_id`; global masks (network-wide
//! enforcement) leave it `None`.

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::channel::ChannelId;

/// Stable mask identifier (16-byte ULID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MaskId(pub Ulid);

impl MaskId {
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

impl Default for MaskId {
    fn default() -> Self {
        Self::new()
    }
}

/// Three list types share a single table. Storage stores the discriminant
/// as `INTEGER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(i64)]
pub enum MaskKind {
    /// `+b` ban — Shade's auto-kick / auto-set list.
    Ban = 1,
    /// `+e` exempt — overrides matching bans.
    Exempt = 2,
    /// `+I` invite — bypasses `+i` on channels.
    Invite = 3,
}

impl MaskKind {
    /// Wire/storage discriminant.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self as i64
    }

    /// Reverse mapping; returns `None` for unknown values.
    #[must_use]
    pub const fn from_i64(v: i64) -> Option<Self> {
        match v {
            1 => Some(Self::Ban),
            2 => Some(Self::Exempt),
            3 => Some(Self::Invite),
            _ => None,
        }
    }
}

/// One row in the unified mask list table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mask {
    pub id: MaskId,
    pub kind: MaskKind,
    /// `None` for network-wide global masks.
    pub channel_id: Option<ChannelId>,
    /// IRC-style hostmask (`nick!user@host`, with `*`/`?` wildcards).
    pub mask: String,
    pub reason: Option<String>,
    /// Free-form "set by" identifier (handle, nick!user@host, etc.).
    pub set_by: Option<String>,
    /// Unix milliseconds.
    pub set_at: i64,
    /// Unix milliseconds; `None` for permanent masks.
    pub expires_at: Option<i64>,
    /// Sticky bans aren't auto-removed by Shade after the IRCD's own ban
    /// expiry timer fires.
    pub sticky: bool,
    pub updated_at: i64,
    pub origin_node: String,
}

/// Inputs to create a new mask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewMask {
    pub kind: MaskKind,
    #[serde(default)]
    pub channel_id: Option<ChannelId>,
    pub mask: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub set_by: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub sticky: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_round_trips_through_i64() {
        for kind in [MaskKind::Ban, MaskKind::Exempt, MaskKind::Invite] {
            assert_eq!(MaskKind::from_i64(kind.as_i64()), Some(kind));
        }
        assert_eq!(MaskKind::from_i64(99), None);
    }

    #[test]
    fn kind_serializes_as_lowercase_string() {
        let j = serde_json::to_string(&MaskKind::Ban).unwrap();
        assert_eq!(j, "\"ban\"");
        let back: MaskKind = serde_json::from_str("\"exempt\"").unwrap();
        assert_eq!(back, MaskKind::Exempt);
    }
}
