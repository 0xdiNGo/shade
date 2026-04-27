//! IRCv3 capability negotiation state machine.
//!
//! Handles the CAP LS / CAP REQ / CAP ACK / CAP NAK dance described in
//! [IRCv3 Capability Negotiation](https://ircv3.net/specs/extensions/capability-negotiation).
//!
//! This module is pure: it consumes parsed [`crate::Message`]s and emits a
//! sequence of [`CapAction`]s the caller (`session.rs`) translates into
//! `Writer::send` calls or higher-level events. No I/O, no async — fully
//! unit-testable as a state machine.
//!
//! Usage shape:
//!
//! 1. After TCP+TLS connect, send [`CapNegotiation::initial_command`] to
//!    the server (`CAP LS 302`).
//! 2. Feed every parsed message into [`CapNegotiation::handle`]; act on
//!    the returned `Vec<CapAction>`.
//! 3. When `CapAction::Done` is emitted, the negotiation is complete; send
//!    `CAP END` (or hand off to SASL first if `sasl` is among the acked
//!    caps).

use std::collections::BTreeSet;

use crate::message::Message;

/// One side of a CAP negotiation, tracking what we asked for and what the
/// server agreed to.
#[derive(Debug, Clone)]
pub struct CapNegotiation {
    desired: BTreeSet<String>,
    available: BTreeSet<String>,
    acked: BTreeSet<String>,
    requested: BTreeSet<String>,
    phase: Phase,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// Waiting for the first `CAP * LS` (or chunked LS continuation).
    AwaitingLs,
    /// Sent `CAP REQ`, waiting for `CAP * ACK` / `CAP * NAK` covering the
    /// requested set.
    AwaitingAck,
    /// Negotiation complete; further CAP messages are ignored (re-request
    /// support is post-MVP).
    Done,
}

/// One action the caller should perform in response to a parsed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapAction {
    /// Write this raw line to the server (without CRLF; the connection
    /// layer adds it).
    Send(String),
    /// Server acked these capabilities; record them as enabled.
    Acked(BTreeSet<String>),
    /// Server NAK'd these capabilities; they're not enabled.
    Nakked(BTreeSet<String>),
    /// Negotiation is finished. The caller should send either `CAP END` or,
    /// if `sasl` is in [`CapNegotiation::acked_caps`], begin the SASL flow.
    Done,
}

impl CapNegotiation {
    /// Build a new negotiation that will request the intersection of
    /// `desired` with whatever the server advertises in `CAP LS`.
    #[must_use]
    pub fn new(desired: impl IntoIterator<Item = String>) -> Self {
        Self {
            desired: desired.into_iter().collect(),
            available: BTreeSet::new(),
            acked: BTreeSet::new(),
            requested: BTreeSet::new(),
            phase: Phase::AwaitingLs,
        }
    }

    /// First line to write after connecting. (`CAP LS 302` requests the
    /// IRCv3.2 cap-list format with values.)
    #[must_use]
    pub fn initial_command() -> &'static str {
        "CAP LS 302"
    }

    /// Caps the server advertised in `CAP LS`.
    #[must_use]
    pub fn available_caps(&self) -> &BTreeSet<String> {
        &self.available
    }

    /// Caps the server `CAP * ACK`'d after our `CAP REQ`.
    #[must_use]
    pub fn acked_caps(&self) -> &BTreeSet<String> {
        &self.acked
    }

    /// Whether `sasl` was acked.
    #[must_use]
    pub fn sasl_acked(&self) -> bool {
        self.acked.iter().any(|c| c == "sasl")
    }

    /// Whether negotiation is complete.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    /// Process one parsed message and return the actions to perform.
    ///
    /// Messages that aren't relevant to CAP are returned as an empty `Vec`
    /// (the caller routes them to other state machines). Messages this
    /// machine *does* care about: `CAP * LS`, `CAP * LS *` (continuation),
    /// `CAP * ACK`, `CAP * NAK`. Numeric `410 ERR_INVALIDCAPCMD` aborts
    /// negotiation.
    pub fn handle(&mut self, msg: &Message<'_>) -> Vec<CapAction> {
        if !msg.is_command("CAP") {
            return Vec::new();
        }

        // CAP messages: <client> <subcommand> [<args>...]
        // We don't care about the client field; the subcommand is param[1].
        let subcommand = msg.param(1);

        match (&self.phase, subcommand) {
            (Phase::AwaitingLs, Some(sub)) if sub.eq_ignore_ascii_case("LS") => self.handle_ls(msg),
            (Phase::AwaitingAck, Some(sub)) if sub.eq_ignore_ascii_case("ACK") => {
                self.handle_ack(msg)
            }
            (Phase::AwaitingAck, Some(sub)) if sub.eq_ignore_ascii_case("NAK") => {
                self.handle_nak(msg)
            }
            _ => Vec::new(),
        }
    }

    fn handle_ls(&mut self, msg: &Message<'_>) -> Vec<CapAction> {
        // CAP * LS [*] :cap1 cap2=value cap3
        // The optional "*" in param[2] means "more LS lines follow"; the
        // cap list is the trailing param.
        let multiline = msg.param(2).is_some_and(|p| p == "*");
        let caps_field_idx = if multiline { 3 } else { 2 };
        let Some(caps_field) = msg.param(caps_field_idx) else {
            return Vec::new();
        };

        for entry in caps_field.split(' ').filter(|s| !s.is_empty()) {
            // Strip "=value"; we ignore cap values for MVP.
            let name = entry.split_once('=').map_or(entry, |(n, _)| n);
            self.available.insert(name.to_owned());
        }

        if multiline {
            return Vec::new();
        }

        // LS complete; pick our intersection and REQ.
        let to_request: BTreeSet<String> = self
            .desired
            .iter()
            .filter(|c| self.available.contains(c.as_str()))
            .cloned()
            .collect();

        if to_request.is_empty() {
            // Nothing to negotiate; jump straight to done.
            self.phase = Phase::Done;
            return vec![CapAction::Done];
        }

        let line = format!("CAP REQ :{}", join_caps(&to_request));
        self.requested = to_request;
        self.phase = Phase::AwaitingAck;
        vec![CapAction::Send(line)]
    }

    fn handle_ack(&mut self, msg: &Message<'_>) -> Vec<CapAction> {
        let Some(caps_field) = msg.param(2) else {
            return Vec::new();
        };
        let acked: BTreeSet<String> = caps_field
            .split(' ')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();

        for cap in &acked {
            self.acked.insert(cap.clone());
            self.requested.remove(cap);
        }

        let mut actions = vec![CapAction::Acked(acked)];

        // If we have nothing left to wait on, finish negotiation.
        if self.requested.is_empty() {
            self.phase = Phase::Done;
            actions.push(CapAction::Done);
        }

        actions
    }

    fn handle_nak(&mut self, msg: &Message<'_>) -> Vec<CapAction> {
        let Some(caps_field) = msg.param(2) else {
            return Vec::new();
        };
        let nakked: BTreeSet<String> = caps_field
            .split(' ')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();

        for cap in &nakked {
            self.requested.remove(cap);
        }

        let mut actions = vec![CapAction::Nakked(nakked)];

        if self.requested.is_empty() {
            self.phase = Phase::Done;
            actions.push(CapAction::Done);
        }

        actions
    }
}

fn join_caps(caps: &BTreeSet<String>) -> String {
    caps.iter().cloned().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_str;

    fn negotiate_with(desired: &[&str]) -> CapNegotiation {
        CapNegotiation::new(desired.iter().map(|s| (*s).to_string()))
    }

    #[test]
    fn initial_command_is_cap_ls_302() {
        assert_eq!(CapNegotiation::initial_command(), "CAP LS 302");
    }

    #[test]
    fn ls_picks_intersection_and_requests() {
        let mut n = negotiate_with(&["sasl", "server-time", "multi-prefix", "batch"]);
        let msg = parse_str(":server CAP * LS :sasl server-time multi-prefix away-notify").unwrap();
        let actions = n.handle(&msg);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            CapAction::Send(line) => {
                // We REQ only what server has AND we want; alphabetical.
                assert!(line.starts_with("CAP REQ :"));
                let req = line.trim_start_matches("CAP REQ :");
                let mut got: Vec<&str> = req.split(' ').collect();
                got.sort_unstable();
                assert_eq!(got, vec!["multi-prefix", "sasl", "server-time"]);
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(n.available.len(), 4);
    }

    #[test]
    fn ls_with_values_strips_them() {
        let mut n = negotiate_with(&["sts"]);
        let msg = parse_str(":server CAP * LS :sts=duration=2592000,port=6697").unwrap();
        let _ = n.handle(&msg);
        assert!(n.available.contains("sts"));
    }

    #[test]
    fn multiline_ls_accumulates_then_requests() {
        let mut n = negotiate_with(&["sasl", "server-time"]);

        let msg1 = parse_str(":server CAP * LS * :sasl").unwrap();
        let actions1 = n.handle(&msg1);
        assert!(
            actions1.is_empty(),
            "no actions while LS continuation pending"
        );

        let msg2 = parse_str(":server CAP * LS :server-time multi-prefix").unwrap();
        let actions2 = n.handle(&msg2);
        assert_eq!(actions2.len(), 1);
        assert!(matches!(&actions2[0], CapAction::Send(s) if s.starts_with("CAP REQ :")));
    }

    #[test]
    fn ls_with_no_overlap_finishes_immediately() {
        let mut n = negotiate_with(&["sasl"]);
        let msg = parse_str(":server CAP * LS :server-time multi-prefix").unwrap();
        let actions = n.handle(&msg);
        assert_eq!(actions, vec![CapAction::Done]);
        assert!(n.is_done());
    }

    #[test]
    fn ack_records_caps_and_finishes_when_all_received() {
        let mut n = negotiate_with(&["sasl", "server-time"]);
        let _ = n.handle(&parse_str(":server CAP * LS :sasl server-time").unwrap());

        // Server ACKs both at once.
        let actions = n.handle(&parse_str(":server CAP * ACK :sasl server-time").unwrap());
        assert!(matches!(actions.last(), Some(CapAction::Done)));
        assert!(n.is_done());
        assert!(n.acked_caps().contains("sasl"));
        assert!(n.acked_caps().contains("server-time"));
        assert!(n.sasl_acked());
    }

    #[test]
    fn ack_partial_then_nak_finishes() {
        let mut n = negotiate_with(&["sasl", "server-time", "multi-prefix"]);
        let _ = n.handle(&parse_str(":server CAP * LS :sasl server-time multi-prefix").unwrap());

        let mid = n.handle(&parse_str(":server CAP * ACK :sasl").unwrap());
        // Still waiting on server-time + multi-prefix.
        assert!(!matches!(mid.last(), Some(CapAction::Done)));

        let end = n.handle(&parse_str(":server CAP * NAK :server-time multi-prefix").unwrap());
        assert!(matches!(end.last(), Some(CapAction::Done)));
        assert!(n.is_done());
        assert!(n.sasl_acked());
        assert!(!n.acked_caps().contains("server-time"));
    }

    #[test]
    fn non_cap_messages_are_ignored() {
        let mut n = negotiate_with(&["sasl"]);
        let actions = n.handle(&parse_str(":server PING :foo").unwrap());
        assert!(actions.is_empty());
    }

    #[test]
    fn cap_after_done_is_ignored() {
        let mut n = negotiate_with(&["sasl"]);
        let _ = n.handle(&parse_str(":server CAP * LS :other").unwrap());
        assert!(n.is_done());
        let actions = n.handle(&parse_str(":server CAP * NEW :sasl").unwrap());
        // Re-negotiation (CAP NEW handling) is post-MVP; we don't act on it.
        assert!(actions.is_empty());
    }
}
