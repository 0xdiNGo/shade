//! Deterministic role distribution.
//!
//! Each Shade node, given the same set of eligible peers and the same
//! channel name, computes the *same* assignment for each role. No leader
//! election. No consensus. Same input → same output everywhere.
//!
//! Algorithm (mirrors Wraith's `rebalance_roles_chan` at
//! `src/mod/irc.mod/irc.cc:1818`):
//!
//! 1. Build the eligible-peer list and sort by `node_id` lexicographically.
//! 2. For each role at index `i`, assign `slots_for(role)` peers starting
//!    at offset `i % len`, walking forward with wraparound.
//!
//! The role-to-index ordering is stable across nodes — we use the order
//! defined by [`crate::ROLE_COUNTS`].

use std::collections::BTreeMap;

use crate::role::{Role, ROLE_COUNTS};

/// Compute the role → assigned-peers map for a single channel.
///
/// `eligible_peers` should be the set of peers that are mesh-connected,
/// joined to the channel, opped, and advertise the `roles` feature in
/// `PeerHello`. The function does not enforce these preconditions; the
/// caller is responsible.
///
/// Returns the assignment as a `BTreeMap` so iteration order is also
/// stable across nodes.
#[must_use]
pub fn compute_assignment(eligible_peers: &[String]) -> BTreeMap<Role, Vec<String>> {
    let mut sorted: Vec<String> = eligible_peers.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut out = BTreeMap::new();
    if sorted.is_empty() {
        for &(role, _) in ROLE_COUNTS {
            out.insert(role, Vec::new());
        }
        return out;
    }
    for (idx, &(role, slots)) in ROLE_COUNTS.iter().enumerate() {
        let n = usize::from(slots);
        let start = idx % sorted.len();
        let take = n.min(sorted.len()); // never more peers than we have
        let mut peers = Vec::with_capacity(take);
        for offset in 0..take {
            let i = (start + offset) % sorted.len();
            peers.push(sorted[i].clone());
        }
        out.insert(role, peers);
    }
    out
}

/// True if `node_id` is one of the peers assigned to `role` for this
/// channel under the deterministic rotation.
#[must_use]
pub fn holds_role(eligible_peers: &[String], node_id: &str, role: Role) -> bool {
    compute_assignment(eligible_peers)
        .get(&role)
        .is_some_and(|peers| peers.iter().any(|p| p == node_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_peer_set_yields_empty_assignments_for_every_role() {
        let m = compute_assignment(&[]);
        for &(role, _) in ROLE_COUNTS {
            assert!(m.get(&role).unwrap().is_empty(), "{role:?}");
        }
    }

    #[test]
    fn single_peer_holds_every_role_capped_at_one_slot() {
        let m = compute_assignment(&["node-a".into()]);
        for &(role, _) in ROLE_COUNTS {
            assert_eq!(m.get(&role).unwrap(), &["node-a".to_string()], "{role:?}");
        }
    }

    #[test]
    fn assignment_is_stable_under_input_permutation() {
        let a = compute_assignment(&["node-a".into(), "node-b".into(), "node-c".into()]);
        let b = compute_assignment(&["node-c".into(), "node-a".into(), "node-b".into()]);
        assert_eq!(a, b, "sorting + dedup should make order irrelevant");
    }

    #[test]
    fn assignment_is_stable_under_duplicate_inputs() {
        let a = compute_assignment(&["node-a".into(), "node-a".into(), "node-b".into()]);
        let b = compute_assignment(&["node-a".into(), "node-b".into()]);
        assert_eq!(a, b);
    }

    #[test]
    fn three_peers_each_role_idx_starts_at_distinct_offset() {
        let peers = vec!["a".into(), "b".into(), "c".into()];
        let m = compute_assignment(&peers);
        // Role at index 0 (Voice, 1 slot) → starts at offset 0 → ["a"].
        assert_eq!(m.get(&Role::Voice).unwrap(), &vec!["a".to_string()]);
        // Role at index 1 (Flood, 3 slots) → starts at offset 1 → ["b", "c", "a"].
        assert_eq!(
            m.get(&Role::Flood).unwrap(),
            &vec!["b".to_string(), "c".to_string(), "a".to_string()]
        );
        // Role at index 2 (Op, 1 slot) → offset 2 → ["c"].
        assert_eq!(m.get(&Role::Op).unwrap(), &vec!["c".to_string()]);
        // Role at index 3 (Deop, 1 slot) → offset 3 % 3 = 0 → ["a"].
        assert_eq!(m.get(&Role::Deop).unwrap(), &vec!["a".to_string()]);
    }

    #[test]
    fn slots_capped_to_peer_count() {
        // Flood needs 3 slots; with only 2 peers, we get [b, a] (start
        // offset 1 % 2 = 1) — never 3 entries.
        let m = compute_assignment(&["a".into(), "b".into()]);
        assert_eq!(m.get(&Role::Flood).unwrap().len(), 2);
    }

    #[test]
    fn holds_role_consistent_with_assignment() {
        let peers: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        for &(role, _) in ROLE_COUNTS {
            let assignment = compute_assignment(&peers);
            for peer in &peers {
                let expected = assignment.get(&role).unwrap().contains(peer);
                assert_eq!(
                    holds_role(&peers, peer, role),
                    expected,
                    "{peer} for {role:?}"
                );
            }
        }
    }
}
