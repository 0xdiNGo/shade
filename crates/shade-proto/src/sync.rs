//! Snapshot + delta gossip messages.
//!
//! On connect, the requester sends [`SnapshotRequest`] with the highest
//! `updated_at` it has previously seen from this peer; the peer streams
//! one or more [`SnapshotChunk`]s containing rows newer than that
//! watermark. Steady-state mutations broadcast as [`Upsert`] / [`Delete`].

use serde::{Deserialize, Serialize};
use shade_core::{
    Channel, ChannelId, ChannelSettings, ChannelUserFlags, Mask, MaskId, User, UserId,
};

/// "Catch me up on rows newer than `since_ts`" — sent by the requester
/// once after the [`crate::PeerHello`] exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRequest {
    /// Highest `updated_at` (Unix ms) the requester has previously seen
    /// from this peer. Use `0` for a full snapshot.
    pub since_ts: i64,
}

/// One page of snapshot rows. `more = true` means at least one further
/// chunk is on the way; `more = false` is the terminating chunk and may
/// itself carry zero entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotChunk {
    pub entries: Vec<SnapshotEntry>,
    /// `false` on the final chunk for a given snapshot exchange.
    pub more: bool,
}

/// One row inside a [`SnapshotChunk`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SnapshotEntry {
    User(User),
    Channel(Channel),
    ChannelSettings(ChannelSettings),
    ChannelUserFlags(ChannelUserFlags),
    Mask(Mask),
}

/// Live mutation broadcast during steady-state gossip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upsert {
    #[serde(flatten)]
    pub kind: UpsertKind,
}

/// What kind of row was upserted. The row payload carries its own
/// `(updated_at, origin_node)` for LWW resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UpsertKind {
    User(User),
    Channel(Channel),
    ChannelSettings(ChannelSettings),
    ChannelUserFlags(ChannelUserFlags),
    Mask(Mask),
}

/// Live deletion broadcast during steady-state gossip. Carries its own
/// `(updated_at, origin_node)` so receivers can apply LWW even against a
/// concurrent upsert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delete {
    #[serde(flatten)]
    pub kind: DeleteKind,
    pub updated_at: i64,
    pub origin_node: String,
}

/// What was deleted. Composite-key tables (`channel_user_flags`) carry
/// both halves of the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeleteKind {
    User {
        id: UserId,
    },
    Channel {
        id: ChannelId,
    },
    ChannelUserFlags {
        channel_id: ChannelId,
        user_id: UserId,
    },
    Mask {
        id: MaskId,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(v: &T) {
        let bytes = rmp_serde::to_vec_named(v).unwrap();
        let back: T = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(*v, back);
    }

    #[test]
    fn snapshot_request_round_trips() {
        round_trip(&SnapshotRequest {
            since_ts: 1_700_000_000_000,
        });
    }

    #[test]
    fn empty_snapshot_chunk_is_legal() {
        round_trip(&SnapshotChunk {
            entries: Vec::new(),
            more: false,
        });
    }

    #[test]
    fn delete_kind_with_composite_key_round_trips() {
        round_trip(&Delete {
            kind: DeleteKind::ChannelUserFlags {
                channel_id: ChannelId::from_bytes([1; 16]),
                user_id: UserId::from_bytes([2; 16]),
            },
            updated_at: 1,
            origin_node: "node-a".into(),
        });
    }
}
