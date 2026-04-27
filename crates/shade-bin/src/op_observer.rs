//! Cross-bot op observation: cookie verification + mass-op detection
//! + mass-op response.
//!
//! Every Shade node feeds the `MODE` and `NOTICE` events it sees on
//! channels into one of these observers. The observer:
//!
//! * **Verifies cookies.** A cookie NOTICE (`NOTICE #c
//!   :shade-cookie/<wire>`) within `COOKIE_GRACE_MS` of an observed
//!   `MODE +o nick` from the same source authorizes that op. The
//!   matching pending op + history entry are removed (so legitimate
//!   role-holder ops never trip the mass-op counter). If the grace
//!   window passes with no matching cookie, the op is flagged as
//!   **uncertified** (potentially a hijacked bot).
//! * **Detects mass-op.** Sliding window per `(channel, source)`: more
//!   than `MASS_OP_THRESHOLD` *uncertified* ops within
//!   `MASS_OP_WINDOW_MS` from the same source trips
//!   [`MassOpAction::Deop`], which the daemon turns into a `MODE -o`
//!   for every recently-opped victim plus an audit entry. After a
//!   trip, further ops from the same `(channel, source)` are
//!   suppressed for `MASS_OP_COOLDOWN_MS` to avoid op-deop flapping.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use shade_core::{cookies, ReplayGuard};
use tracing::{debug, info, warn};

/// Time after a `MODE +o` we'll accept a matching cookie NOTICE.
pub const COOKIE_GRACE_MS: i64 = 5_000;

/// Max ops within the window before we flag mass-op behavior.
pub const MASS_OP_THRESHOLD: usize = 5;

/// Sliding window for the mass-op counter.
pub const MASS_OP_WINDOW_MS: i64 = 10_000;

/// After a trip, suppress further trips for the same `(channel, source)`
/// pair until this much wall-clock time has passed. Avoids the daemon
/// flapping op→deop→op→deop when a legitimate but mistaken operator
/// re-ops the same victims after a deop.
pub const MASS_OP_COOLDOWN_MS: i64 = 60_000;

/// Periodic sweep cadence — drops expired pending ops and trims the
/// per-source mass-op counter.
pub const SWEEP_INTERVAL_MS: i64 = 1_000;

/// Channel-scoped key derivation needs the mesh PSK and the channel
/// name; this is the same `Arc<[u8]>` the daemon holds.
///
/// `node_id` isn't load-bearing for verification (the cookie carries
/// the *issuer's* node id, which we cross-check against role
/// assignment in M5 PR3 follow-up), but threading it here keeps the
/// log lines self-contained.
#[derive(Clone)]
pub struct ObserverContext {
    #[allow(dead_code)]
    pub node_id: Arc<str>,
    pub mesh_psk: Arc<[u8]>,
}

#[derive(Debug, Clone)]
struct PendingOp {
    channel: String,
    target_nick: String,
    source: String,
    ts_ms: i64,
}

#[derive(Debug, Clone)]
struct OpEvent {
    source: String,
    channel: String,
    target_nick: String,
    ts_ms: i64,
}

/// Action the daemon should take in response to an observation.
///
/// Today the only action is `Deop`: when an uncertified source breaches
/// the mass-op threshold, the daemon issues `MODE -o` for every nick
/// that source recently opped within the window. Future variants might
/// include lockdown (`MODE +mR`) or peer quarantine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MassOpAction {
    /// Reverse the recent ops by `source` on `channel`. `victims` are
    /// the nicks observed in the sliding window.
    Deop {
        channel: String,
        source: String,
        victims: Vec<String>,
    },
}

/// Per-process state for cookie verification + mass-op detection.
#[derive(Debug)]
pub struct OpObserver {
    pending: VecDeque<PendingOp>,
    /// Window of *uncertified* ops only — entries are dropped as soon as
    /// a matching cookie NOTICE verifies them, so role-holder ops never
    /// trip the mass-op counter.
    op_history: VecDeque<OpEvent>,
    replay: ReplayGuard,
    last_sweep_ms: i64,
    /// Per-`(channel, source)` cooldown: once mass-op response fires,
    /// suppress re-trip until `cooldowns[k] <= now`. Limits the deop
    /// storm to one per cooldown window even if the rogue source keeps
    /// opping.
    cooldowns: HashMap<(String, String), i64>,
}

impl OpObserver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            op_history: VecDeque::new(),
            replay: ReplayGuard::new(),
            // i64::MIN guarantees the first observed timestamp triggers
            // a sweep on its first record_op or record_cookie_notice
            // call — and lets tests use synthetic timestamps without
            // racing the real clock.
            last_sweep_ms: i64::MIN,
            cooldowns: HashMap::new(),
        }
    }

    /// Record an observed `MODE +o nick` on `channel` from `source`.
    /// `source` is the IRC source (`nick!user@host` or server name).
    /// `now_ms` is `shade_core::now_ms()` at observation time — passed
    /// as a parameter so tests can drive deterministic clocks.
    ///
    /// Returns [`Some(MassOpAction)`] when the mass-op threshold trips
    /// for this `(channel, source)` pair (and the cooldown isn't
    /// active). The daemon should turn the action into the
    /// corresponding IRC modes plus an audit entry.
    #[must_use]
    pub fn record_op(
        &mut self,
        channel: &str,
        target_nick: &str,
        source: &str,
        now_ms: i64,
    ) -> Option<MassOpAction> {
        self.pending.push_back(PendingOp {
            channel: channel.to_owned(),
            target_nick: target_nick.to_owned(),
            source: source.to_owned(),
            ts_ms: now_ms,
        });
        self.op_history.push_back(OpEvent {
            source: source.to_owned(),
            channel: channel.to_owned(),
            target_nick: target_nick.to_owned(),
            ts_ms: now_ms,
        });
        let action = self.check_mass_op(source, channel, now_ms);
        self.maybe_sweep(now_ms);
        action
    }

    /// Try to consume a `NOTICE shade-cookie/<wire>` to authorize a
    /// pending op. Returns `true` if the cookie verified and matched a
    /// pending op; `false` otherwise (caller can log).
    pub fn record_cookie_notice(
        &mut self,
        channel: &str,
        wire: &str,
        ctx: &ObserverContext,
        now_ms: i64,
    ) -> bool {
        let key = shade_core::derive_channel_key(&ctx.mesh_psk, channel);
        let Ok(cookie) = cookies::verify(wire, &key, &mut self.replay) else {
            warn!(%channel, "op-observer: cookie NOTICE failed verification");
            return false;
        };
        // Find the matching pending op (same channel + nick, within grace).
        let idx = self.pending.iter().position(|p| {
            p.channel == channel
                && p.target_nick == cookie.target_nick
                && now_ms - p.ts_ms <= COOKIE_GRACE_MS
        });
        if let Some(i) = idx {
            let op = self.pending.remove(i).unwrap();
            // Drop the matching history entry so this certified op
            // doesn't contribute to the mass-op counter. Same key:
            // (channel, source, target_nick) within the grace window.
            if let Some(h) = self.op_history.iter().position(|e| {
                e.channel == op.channel
                    && e.target_nick == op.target_nick
                    && e.source == op.source
                    && now_ms - e.ts_ms <= COOKIE_GRACE_MS
            }) {
                self.op_history.remove(h);
            }
            info!(
                %channel,
                target = %op.target_nick,
                source = %op.source,
                requester = %cookie.requester_node_id,
                "op-observer: op certified by cookie"
            );
            self.maybe_sweep(now_ms);
            true
        } else {
            debug!(%channel, "op-observer: cookie verified but no matching pending op");
            self.maybe_sweep(now_ms);
            false
        }
    }

    /// Drop pending ops older than `COOKIE_GRACE_MS` and emit a
    /// warning for each. Trims `op_history` to `MASS_OP_WINDOW_MS`.
    /// Idempotent across calls.
    pub fn maybe_sweep(&mut self, now_ms: i64) {
        // saturating_sub so `last_sweep_ms = i64::MIN` (initial state)
        // doesn't overflow; the first call always sweeps.
        if now_ms.saturating_sub(self.last_sweep_ms) < SWEEP_INTERVAL_MS {
            return;
        }
        self.last_sweep_ms = now_ms;
        while let Some(front) = self.pending.front() {
            if now_ms - front.ts_ms <= COOKIE_GRACE_MS {
                break;
            }
            let expired = self.pending.pop_front().unwrap();
            warn!(
                channel = %expired.channel,
                target = %expired.target_nick,
                source = %expired.source,
                age_ms = now_ms - expired.ts_ms,
                "op-observer: uncertified op (no matching cookie within grace window)"
            );
        }
        while let Some(front) = self.op_history.front() {
            if now_ms - front.ts_ms <= MASS_OP_WINDOW_MS {
                break;
            }
            self.op_history.pop_front();
        }
    }

    fn check_mass_op(&mut self, source: &str, channel: &str, now_ms: i64) -> Option<MassOpAction> {
        let key = (channel.to_owned(), source.to_owned());
        if let Some(&until) = self.cooldowns.get(&key) {
            if now_ms < until {
                return None;
            }
        }
        let recent: Vec<&OpEvent> = self
            .op_history
            .iter()
            .filter(|e| {
                e.source == source && e.channel == channel && now_ms - e.ts_ms <= MASS_OP_WINDOW_MS
            })
            .collect();
        if recent.len() < MASS_OP_THRESHOLD {
            return None;
        }
        let victims: Vec<String> = recent.iter().map(|e| e.target_nick.clone()).collect();
        warn!(
            %source, %channel, count = victims.len(), window_ms = MASS_OP_WINDOW_MS,
            "op-observer: mass-op threshold tripped — emitting deop response"
        );
        self.cooldowns.insert(key, now_ms + MASS_OP_COOLDOWN_MS);
        Some(MassOpAction::Deop {
            channel: channel.to_owned(),
            source: source.to_owned(),
            victims,
        })
    }
}

impl Default for OpObserver {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the cookie wire form from a `NOTICE` body, if present. The
/// expected shape is `shade-cookie/<wire>`; surrounding whitespace is
/// trimmed.
#[must_use]
pub fn extract_cookie_wire(body: &str) -> Option<&str> {
    body.trim().strip_prefix("shade-cookie/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(psk: &[u8]) -> ObserverContext {
        ObserverContext {
            node_id: Arc::from("node-test"),
            mesh_psk: Arc::from(psk.to_vec().into_boxed_slice()),
        }
    }

    fn make_cookie(channel: &str, target_nick: &str, psk: &[u8]) -> String {
        let key = shade_core::derive_channel_key(psk, channel);
        let cookie = shade_core::Cookie::new("node-issuer", target_nick);
        shade_core::cookies::make(&cookie, &key).unwrap()
    }

    #[test]
    fn cookie_notice_within_grace_window_certifies_op() {
        let psk = b"the-shared-mesh-psk";
        let mut obs = OpObserver::new();
        let _ = obs.record_op("#c", "alice", "shade-iad-01!u@h", 1_000);
        let wire = make_cookie("#c", "alice", psk);
        let ok = obs.record_cookie_notice("#c", &wire, &ctx(psk), 1_500);
        assert!(ok, "cookie should certify the pending op");
    }

    #[test]
    fn cookie_notice_after_grace_does_not_match() {
        let psk = b"the-shared-mesh-psk";
        let mut obs = OpObserver::new();
        let _ = obs.record_op("#c", "alice", "shade-iad-01!u@h", 1_000);
        let wire = make_cookie("#c", "alice", psk);
        // 6 seconds later — beyond COOKIE_GRACE_MS = 5s. Sweep happens
        // first, op is dropped.
        let ok = obs.record_cookie_notice("#c", &wire, &ctx(psk), 7_000);
        assert!(!ok);
    }

    #[test]
    fn cookie_with_wrong_psk_is_rejected() {
        let mut obs = OpObserver::new();
        let _ = obs.record_op("#c", "alice", "src", 1_000);
        let wire = make_cookie("#c", "alice", b"key-a");
        let ok = obs.record_cookie_notice("#c", &wire, &ctx(b"key-b"), 1_500);
        assert!(!ok);
    }

    #[test]
    fn unrelated_cookie_does_not_consume_pending_op() {
        let psk = b"some-psk";
        let mut obs = OpObserver::new();
        let _ = obs.record_op("#c", "alice", "src", 1_000);
        let wire = make_cookie("#c", "bob", psk); // wrong target
        let ok = obs.record_cookie_notice("#c", &wire, &ctx(psk), 1_500);
        assert!(!ok);
        // Pending op is still there.
        assert_eq!(obs.pending.len(), 1);
    }

    #[test]
    fn mass_op_threshold_returns_deop_action_with_victims() {
        let mut obs = OpObserver::new();
        // 4 ops are below threshold — no action.
        for (i, victim) in ["a", "b", "c", "d"].iter().enumerate() {
            let action = obs.record_op(
                "#c",
                victim,
                "rogue!u@h",
                1_000 + i64::try_from(i).unwrap() * 100,
            );
            assert!(action.is_none());
        }
        // 5th op trips threshold → Deop action.
        let action = obs.record_op("#c", "e", "rogue!u@h", 1_500);
        match action {
            Some(MassOpAction::Deop {
                channel,
                source,
                victims,
            }) => {
                assert_eq!(channel, "#c");
                assert_eq!(source, "rogue!u@h");
                assert_eq!(victims, vec!["a", "b", "c", "d", "e"]);
            }
            None => panic!("expected MassOpAction::Deop"),
        }
    }

    #[test]
    fn cookie_certified_ops_do_not_trip_mass_op() {
        let psk = b"shared-psk";
        let mut obs = OpObserver::new();
        // Issue 6 ops, each immediately followed by a matching cookie
        // NOTICE. None should trip mass-op because cookie verification
        // removes the entry from op_history.
        for i in 0..=MASS_OP_THRESHOLD {
            let now = 1_000 + i64::try_from(i).unwrap() * 200;
            let nick = format!("u{i}");
            let action = obs.record_op("#c", &nick, "shade-peer!u@h", now);
            assert!(action.is_none());
            let wire = make_cookie("#c", &nick, psk);
            let ok = obs.record_cookie_notice("#c", &wire, &ctx(psk), now + 50);
            assert!(ok, "cookie #{i} should certify");
        }
        assert!(
            obs.op_history.is_empty(),
            "all certified ops should be removed from history"
        );
    }

    #[test]
    fn cooldown_suppresses_re_trip_after_action() {
        let mut obs = OpObserver::new();
        // First 4 ops — under threshold, no action.
        for i in 0..(MASS_OP_THRESHOLD - 1) {
            assert!(obs
                .record_op(
                    "#c",
                    &format!("u{i}"),
                    "rogue",
                    1_000 + i64::try_from(i).unwrap() * 100,
                )
                .is_none());
        }
        // 5th op trips — that's MASS_OP_THRESHOLD entries in history.
        assert!(matches!(
            obs.record_op("#c", "u4", "rogue", 1_400),
            Some(MassOpAction::Deop { .. })
        ));
        // Subsequent ops within cooldown do not retrigger.
        for i in 5_usize..12 {
            let action = obs.record_op(
                "#c",
                &format!("u{i}"),
                "rogue",
                1_500 + i64::try_from(i).unwrap() * 100,
            );
            assert!(action.is_none(), "op {i} should be in cooldown");
        }
        // After cooldown expires + new ops accumulate, can trip again.
        // Cooldown is 60s; jump well past it and pump in fresh ops.
        let base = 1_400 + MASS_OP_COOLDOWN_MS + 1_000;
        for i in 0..(MASS_OP_THRESHOLD - 1) {
            let _ = obs.record_op(
                "#c",
                &format!("v{i}"),
                "rogue",
                base + i64::try_from(i).unwrap() * 100,
            );
        }
        assert!(matches!(
            obs.record_op("#c", "v4", "rogue", base + 500),
            Some(MassOpAction::Deop { .. })
        ));
    }

    #[test]
    fn cooldown_is_per_channel_source_pair() {
        let mut obs = OpObserver::new();
        // Trip on (#a, rogue) by sending 5 ops.
        for i in 0..MASS_OP_THRESHOLD {
            let _ = obs.record_op(
                "#a",
                &format!("u{i}"),
                "rogue",
                1_000 + i64::try_from(i).unwrap() * 100,
            );
        }
        // (#b, rogue) starts fresh — different channel, separate cooldown key.
        for i in 0..(MASS_OP_THRESHOLD - 1) {
            let action = obs.record_op(
                "#b",
                &format!("u{i}"),
                "rogue",
                2_000 + i64::try_from(i).unwrap() * 100,
            );
            assert!(action.is_none(), "op {i} on #b under threshold");
        }
        // 5th op on #b trips.
        let action = obs.record_op("#b", "u4", "rogue", 2_400);
        assert!(matches!(action, Some(MassOpAction::Deop { channel, .. }) if channel == "#b"));
    }

    #[test]
    fn sweep_evicts_stale_pending_ops_and_trims_history() {
        let mut obs = OpObserver::new();
        let _ = obs.record_op("#c", "alice", "src", 0);
        let _ = obs.record_op("#c", "bob", "src", 0);
        // Past the grace + window; both should drop.
        obs.maybe_sweep(MASS_OP_WINDOW_MS + 1_000);
        assert!(obs.pending.is_empty());
        assert!(obs.op_history.is_empty());
    }

    #[test]
    fn extract_cookie_wire_handles_leading_whitespace_and_prefix() {
        assert_eq!(extract_cookie_wire("shade-cookie/abc.def"), Some("abc.def"));
        // `trim()` runs first, so leading + trailing whitespace are
        // stripped before the prefix match.
        assert_eq!(
            extract_cookie_wire("  shade-cookie/abc.def "),
            Some("abc.def")
        );
        assert_eq!(extract_cookie_wire("not a cookie"), None);
    }
}
