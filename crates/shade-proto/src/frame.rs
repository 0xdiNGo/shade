//! Top-level frame envelope.
//!
//! [`Frame`] is the outermost mesh message type. Every byte sequence the
//! transport layer emits is one msgpack-encoded `Frame`. The serde tag
//! `kind` makes the wire format self-describing — readers don't need to
//! peek at lengths to know what's coming.

use serde::{Deserialize, Serialize};

use crate::handshake::{Goodbye, PeerHello};
use crate::sync::{Delete, SnapshotChunk, SnapshotRequest, Upsert};

/// Wire-level mesh frame. Tagged enum so msgpack encodes it as
/// `{"kind": "<variant>", ...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Frame {
    /// First frame each side sends after the TLS handshake.
    Hello(PeerHello),
    /// Voluntary close announcement. Optional — transport-layer EOF is
    /// also a valid termination.
    Goodbye(Goodbye),
    /// Request a catch-up of all rows newer than `since_ts`.
    SnapshotRequest(SnapshotRequest),
    /// One page of snapshot rows in response to a [`SnapshotRequest`].
    SnapshotChunk(SnapshotChunk),
    /// A live row mutation broadcast to peers.
    Upsert(Upsert),
    /// A live row deletion broadcast to peers.
    Delete(Delete),
}

/// Errors decoding a frame from msgpack bytes.
#[derive(Debug, thiserror::Error)]
pub enum FrameDecodeError {
    /// The msgpack payload didn't match the [`Frame`] schema.
    #[error("decode: {0}")]
    Decode(#[source] rmp_serde::decode::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{PeerFeatures, PROTO_VERSION};
    use crate::sync::*;
    use shade_core::{Channel, ChannelId, FlagSet, Mask, MaskId, MaskKind, User, UserId};

    fn sample_hello() -> Frame {
        Frame::Hello(PeerHello {
            node_id: "shade-iad-01".into(),
            proto_version: PROTO_VERSION,
            features: PeerFeatures::default(),
            clock_ms: 1_700_000_000_000,
            channels: vec!["#shade-test".into()],
        })
    }

    fn sample_user() -> User {
        User {
            id: UserId::from_bytes([1; 16]),
            handle: "alice".into(),
            password_hash: None,
            is_bot: false,
            global_flags: "+a".parse().unwrap(),
            comment: None,
            hosts: vec!["alice!*@*".into()],
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_000_000,
            last_seen_at: None,
            origin_node: "shade-iad-01".into(),
        }
    }

    fn sample_channel() -> Channel {
        Channel {
            id: ChannelId::from_bytes([2; 16]),
            name: "#shade-test".into(),
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_000_000,
            origin_node: "shade-iad-01".into(),
        }
    }

    fn sample_mask() -> Mask {
        Mask {
            id: MaskId::from_bytes([3; 16]),
            kind: MaskKind::Ban,
            channel_id: Some(ChannelId::from_bytes([2; 16])),
            mask: "*!*@evil.example".into(),
            reason: Some("flooding".into()),
            set_by: Some("alice".into()),
            set_at: 1_700_000_000_000,
            expires_at: None,
            sticky: true,
            updated_at: 1_700_000_000_000,
            origin_node: "shade-iad-01".into(),
        }
    }

    fn round_trip(frame: &Frame) -> Frame {
        let bytes = crate::encode_frame(frame).expect("encode");
        crate::decode_frame(&bytes).expect("decode")
    }

    #[test]
    fn hello_round_trips() {
        let f = sample_hello();
        assert_eq!(round_trip(&f), f);
    }

    #[test]
    fn snapshot_request_round_trips() {
        let f = Frame::SnapshotRequest(SnapshotRequest {
            since_ts: 1_700_000_000_000,
        });
        assert_eq!(round_trip(&f), f);
    }

    #[test]
    fn snapshot_chunk_with_mixed_entries_round_trips() {
        let f = Frame::SnapshotChunk(SnapshotChunk {
            entries: vec![
                SnapshotEntry::User(sample_user()),
                SnapshotEntry::Channel(sample_channel()),
                SnapshotEntry::Mask(sample_mask()),
            ],
            more: true,
        });
        assert_eq!(round_trip(&f), f);
    }

    #[test]
    fn upsert_user_round_trips() {
        let f = Frame::Upsert(Upsert {
            kind: UpsertKind::User(sample_user()),
        });
        assert_eq!(round_trip(&f), f);
    }

    #[test]
    fn upsert_channel_user_flags_round_trips() {
        let f = Frame::Upsert(Upsert {
            kind: UpsertKind::ChannelUserFlags(shade_core::ChannelUserFlags {
                channel_id: ChannelId::from_bytes([2; 16]),
                user_id: UserId::from_bytes([1; 16]),
                flags: "+ov".parse::<FlagSet>().unwrap(),
                updated_at: 1,
                origin_node: "node-a".into(),
            }),
        });
        assert_eq!(round_trip(&f), f);
    }

    #[test]
    fn delete_user_round_trips() {
        let f = Frame::Delete(Delete {
            kind: DeleteKind::User {
                id: UserId::from_bytes([1; 16]),
            },
            updated_at: 1_700_000_000_000,
            origin_node: "node-a".into(),
        });
        assert_eq!(round_trip(&f), f);
    }

    #[test]
    fn delete_mask_round_trips() {
        let f = Frame::Delete(Delete {
            kind: DeleteKind::Mask {
                id: MaskId::from_bytes([3; 16]),
            },
            updated_at: 1_700_000_000_000,
            origin_node: "node-a".into(),
        });
        assert_eq!(round_trip(&f), f);
    }

    #[test]
    fn goodbye_round_trips() {
        let f = Frame::Goodbye(Goodbye {
            reason: Some("draining".into()),
        });
        assert_eq!(round_trip(&f), f);
    }

    #[test]
    fn malformed_bytes_yield_decode_error() {
        let err = crate::decode_frame(&[0xff, 0xff, 0xff]).unwrap_err();
        assert!(matches!(err, FrameDecodeError::Decode(_)));
    }
}
