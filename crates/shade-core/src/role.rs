//! Per-channel bot roles.
//!
//! Wraith assigns each channel-management responsibility (op someone, kick
//! someone, defend the topic, etc.) to a deterministic subset of the linked
//! bots. The same node, given the same set of peers, computes the same
//! assignment everywhere — no leader election. We keep that model.
//!
//! [`Role`] enumerates the roles Shade ships in MVP. The slot counts in
//! [`role_counts`] mirror Wraith's `role_counts[]` table at
//! `src/flags.cc:41-56`. We **drop `RESOLV` entirely**: Wraith uses it to
//! amortize blocking DNS lookups across bots; in Shade every bot resolves
//! locally with `tokio::net::lookup_host` and shares no state. The
//! remaining drop is the rest of Wraith's `revenge` action set, which
//! moves to MVP-out per `docs/Roadmap.md`.

use serde::{Deserialize, Serialize};

/// Per-channel role types. The number of bots assigned to each role is
/// fixed (see [`role_counts`]) and the assignment is computed by sorted
/// `roleidx % botcount` rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(i64)]
pub enum Role {
    Voice = 1,
    Flood = 2,
    Op = 3,
    Deop = 4,
    Kick = 5,
    Ban = 6,
    Topic = 7,
    Limit = 8,
    Revenge = 9,
    ChanMode = 10,
    Protect = 11,
    Invite = 12,
}

impl Role {
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self as i64
    }

    #[must_use]
    pub const fn from_i64(v: i64) -> Option<Self> {
        match v {
            1 => Some(Self::Voice),
            2 => Some(Self::Flood),
            3 => Some(Self::Op),
            4 => Some(Self::Deop),
            5 => Some(Self::Kick),
            6 => Some(Self::Ban),
            7 => Some(Self::Topic),
            8 => Some(Self::Limit),
            9 => Some(Self::Revenge),
            10 => Some(Self::ChanMode),
            11 => Some(Self::Protect),
            12 => Some(Self::Invite),
            _ => None,
        }
    }
}

/// `(role, slots)` table. Source of truth for role distribution; kept
/// alongside [`Role`] so additions stay in lockstep.
///
/// Mirrors Wraith's `role_counts[]` at `src/flags.cc:41-56`, minus
/// `RESOLV` (intentionally dropped — see module-level docs).
pub const ROLE_COUNTS: &[(Role, u8)] = &[
    (Role::Voice, 1),
    (Role::Flood, 3),
    (Role::Op, 1),
    (Role::Deop, 1),
    (Role::Kick, 2),
    (Role::Ban, 2),
    (Role::Topic, 1),
    (Role::Limit, 1),
    (Role::Revenge, 3),
    (Role::ChanMode, 1),
    (Role::Protect, 2),
    (Role::Invite, 1),
];

/// Number of bots assigned to `role`.
#[must_use]
pub const fn slots_for(role: Role) -> u8 {
    let mut i = 0;
    while i < ROLE_COUNTS.len() {
        let (r, n) = ROLE_COUNTS[i];
        if r as i64 == role as i64 {
            return n;
        }
        i += 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_round_trips_through_i64() {
        for &(role, _) in ROLE_COUNTS {
            assert_eq!(Role::from_i64(role.as_i64()), Some(role));
        }
        assert_eq!(Role::from_i64(0), None);
        assert_eq!(Role::from_i64(99), None);
    }

    #[test]
    fn slots_match_wraith_table() {
        // Spot-check a few against `src/flags.cc:41-56`. The full table is
        // the source of truth.
        assert_eq!(slots_for(Role::Op), 1);
        assert_eq!(slots_for(Role::Kick), 2);
        assert_eq!(slots_for(Role::Flood), 3);
        assert_eq!(slots_for(Role::Revenge), 3);
    }

    #[test]
    fn resolv_role_is_absent() {
        // Make sure nobody re-introduces it without updating the docs.
        for &(role, _) in ROLE_COUNTS {
            // No discriminant collides with the Wraith RESOLV slot (9 in
            // their table). Ours uses 9 for Revenge, so the test is really
            // a count check — 12 entries, not 13.
            let _ = role;
        }
        assert_eq!(ROLE_COUNTS.len(), 12);
    }

    #[test]
    fn role_serializes_as_lowercase_string() {
        let j = serde_json::to_string(&Role::Op).unwrap();
        assert_eq!(j, "\"op\"");
        let chanmode: Role = serde_json::from_str("\"chanmode\"").unwrap();
        assert_eq!(chanmode, Role::ChanMode);
    }
}
