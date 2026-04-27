//! Handshake messages exchanged after the TLS handshake completes.

use serde::{Deserialize, Serialize};

/// Mesh wire-protocol version. Bump on any incompatible change. Receivers
/// drop connections from peers advertising a different major version.
pub const PROTO_VERSION: u32 = 1;

/// First frame each side sends after TLS. The receiver validates that
/// `node_id` matches the peer cert's Subject CN / SAN before treating any
/// subsequent frame as authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerHello {
    /// Stable node identifier — must match the peer cert's Subject CN
    /// and one of its SANs.
    pub node_id: String,
    /// `PROTO_VERSION`. Mismatch → drop the connection.
    pub proto_version: u32,
    /// Optional negotiated capabilities. Unknown features are ignored.
    #[serde(default)]
    pub features: PeerFeatures,
    /// Sender's wall-clock at hello-send time, Unix milliseconds.
    /// Useful for skew telemetry; not load-bearing for sync.
    pub clock_ms: i64,
    /// IRC channels the sender currently subscribes to. Used by the
    /// receiver to scope optional per-channel sync (e.g. role
    /// rebalancing). Empty list means "interested in everything."
    #[serde(default)]
    pub channels: Vec<String>,
}

/// Optional feature flags advertised in `PeerHello`. New flags can be
/// added without breaking older peers — unknown booleans default to
/// `false` on deserialize.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerFeatures {
    /// Sender participates in role distribution (`ROLE_OP`, `ROLE_KICK`,
    /// …). Required for cookie-op handshakes — peers without this flag
    /// are mesh-sync-only.
    #[serde(default)]
    pub roles: bool,
    /// Sender will accept `OpRequest` cookie-op handshakes (M5).
    #[serde(default)]
    pub cookie_ops: bool,
}

/// Voluntary close announcement. Optional — transport EOF terminates
/// cleanly too. Useful for distinguishing "draining for upgrade" from
/// "crashed."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Goodbye {
    /// Free-form reason: `"draining"`, `"upgrade"`, ...
    #[serde(default)]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_version_is_one() {
        assert_eq!(PROTO_VERSION, 1);
    }

    #[test]
    fn peer_features_defaults_are_false() {
        let f = PeerFeatures::default();
        assert!(!f.roles);
        assert!(!f.cookie_ops);
    }

    #[test]
    fn peer_hello_serde_round_trip() {
        let h = PeerHello {
            node_id: "shade-iad-01".into(),
            proto_version: PROTO_VERSION,
            features: PeerFeatures {
                roles: true,
                cookie_ops: false,
            },
            clock_ms: 1_700_000_000_000,
            channels: vec!["#shade-test".into(), "#ops".into()],
        };
        let bytes = rmp_serde::to_vec_named(&h).unwrap();
        let back: PeerHello = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn peer_hello_deserializes_with_unknown_features_dropped() {
        // A peer that adds new feature bits we don't know about should
        // still parse — our PeerFeatures only consumes known fields.
        let json = serde_json::json!({
            "node_id": "shade-iad-01",
            "proto_version": 1,
            "features": { "roles": true, "future_flag": true },
            "clock_ms": 0,
            "channels": []
        });
        let h: PeerHello = serde_json::from_value(json).unwrap();
        assert!(h.features.roles);
        assert!(!h.features.cookie_ops);
    }
}
