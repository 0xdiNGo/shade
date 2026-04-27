//! Audit log records.
//!
//! Every API mutation, every in-channel admin action, every mesh-driven
//! state change writes one [`AuditEntry`]. The `details` field is
//! free-form JSON; specific actions document their own payload shape.
//!
//! Audit rows are intentionally *not* replicated by mesh gossip: each node
//! records what *it* did, and operators reconstruct cross-node history by
//! pulling from each node's `audit_log`. This keeps audit honest under
//! partitions — no single node can rewrite a peer's history.

use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// Stable audit-record identifier (16-byte ULID; ULID's monotonic property
/// is load-bearing here — sorting by `id` orders by time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditId(pub Ulid);

impl AuditId {
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

impl Default for AuditId {
    fn default() -> Self {
        Self::new()
    }
}

/// One audit log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: AuditId,
    /// Unix milliseconds.
    pub ts: i64,
    /// Who acted: a Shade user handle (`@alice`), a node ID for
    /// mesh-driven actions (`node:shade-iad-01`), or `system` for daemon
    /// internals.
    pub actor: String,
    /// Imperative verb (`user.create`, `mask.add`, `chanset.update`, ...).
    /// Hierarchical dot-namespaced names are convention, not enforced.
    pub action: String,
    /// Optional target identifier (handle, channel name, mask, ULID, ...).
    pub target: Option<String>,
    /// Free-form JSON payload describing the action. Empty object `{}` if
    /// the action carries no extra data.
    pub details: serde_json::Value,
    /// Origin: `api`, `irc`, `mesh`, `system`. Distinguishes how the
    /// action arrived without overloading `actor`.
    pub source: AuditSource,
}

/// Origin of an audit entry. Distinguishes channels that produced the
/// action even when the actor identity is the same node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSource {
    /// HTTP+JSON admin API.
    Api,
    /// In-channel `/MSG TOKEN` admin command or other IRC-driven action.
    Irc,
    /// Mesh-replicated mutation arriving from a peer.
    Mesh,
    /// Daemon internals (startup, periodic rebalance, etc.).
    System,
}

impl AuditEntry {
    /// Convenience constructor: stamps `id`, `ts` (caller-supplied),
    /// `details=null`, and the rest from the call site. The `null`
    /// details payload reads as JSON `null`; callers that want to
    /// document additional fields should build the value themselves.
    #[must_use]
    pub fn new(
        ts: i64,
        actor: impl Into<String>,
        action: impl Into<String>,
        source: AuditSource,
    ) -> Self {
        Self {
            id: AuditId::new(),
            ts,
            actor: actor.into(),
            action: action.into(),
            target: None,
            details: serde_json::Value::Null,
            source,
        }
    }

    /// Builder-style setter for `target`.
    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Builder-style setter for `details`.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_source_serializes_as_lowercase_string() {
        let j = serde_json::to_string(&AuditSource::Api).unwrap();
        assert_eq!(j, "\"api\"");
        let back: AuditSource = serde_json::from_str("\"mesh\"").unwrap();
        assert_eq!(back, AuditSource::Mesh);
    }

    #[test]
    fn audit_entry_builder_sets_target_and_details() {
        let entry = AuditEntry::new(1_700_000_000_000, "@alice", "mask.add", AuditSource::Api)
            .with_target("#shade-test")
            .with_details(serde_json::json!({"mask": "*!*@evil.example"}));
        assert_eq!(entry.actor, "@alice");
        assert_eq!(entry.target.as_deref(), Some("#shade-test"));
        assert_eq!(entry.details["mask"], "*!*@evil.example");
        assert_eq!(entry.source, AuditSource::Api);
    }

    #[test]
    fn audit_entry_round_trips_through_json() {
        let entry = AuditEntry::new(1, "system", "node.start", AuditSource::System);
        let j = serde_json::to_string(&entry).unwrap();
        let back: AuditEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(entry, back);
    }
}
