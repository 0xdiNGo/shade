//! IRC server state machine.
//!
//! Consumes parsed [`Message`]s and maintains an in-memory model of:
//!
//! - Our own nickname (after RPL_WELCOME).
//! - Per-channel state: members, modes, topic, topic-set-by, topic-set-at.
//! - Per-member state: nick, user, host, mode-prefix flags (e.g. `+o`, `+v`).
//!
//! The state machine emits high-level [`StateEvent`]s the upper-layer
//! consumer (the `session` loop in PR #7) routes to the rest of Shade.
//!
//! Out of scope for this PR: channel-mode-with-args parsing for non-PREFIX
//! modes (bans, exempts, invites, keys, limits) — those need full
//! `CHANMODES` interpretation and ship in M3 alongside the masklist API.
//! `ACCOUNT` and `CHGHOST` consumption ship with the wire-up PR.

use std::collections::{BTreeMap, BTreeSet};

use crate::message::Message;

// ----- prefix map ----------------------------------------------------------

/// Mode-prefix mapping declared by the server in `005 RPL_ISUPPORT`'s
/// `PREFIX=(modes)prefixes` token. Defaults to the standard ircu/Ratbox
/// `(ov)@+` mapping until 005 is parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixMap {
    /// `(mode_letter, prefix_char)` pairs in priority (high-to-low) order.
    entries: Vec<(char, char)>,
}

impl Default for PrefixMap {
    fn default() -> Self {
        Self {
            entries: vec![('o', '@'), ('v', '+')],
        }
    }
}

impl PrefixMap {
    /// Parse a `PREFIX=(modes)prefixes` token. Returns the default if the
    /// token is malformed.
    #[must_use]
    pub fn parse(token: &str) -> Self {
        let Some(rest) = token.strip_prefix('(') else {
            return Self::default();
        };
        let Some((modes, prefixes)) = rest.split_once(')') else {
            return Self::default();
        };
        if modes.chars().count() != prefixes.chars().count() {
            return Self::default();
        }
        Self {
            entries: modes.chars().zip(prefixes.chars()).collect(),
        }
    }

    /// Mode letter associated with a prefix char (e.g. `'@' -> 'o'`).
    #[must_use]
    pub fn mode_for_prefix(&self, prefix: char) -> Option<char> {
        self.entries
            .iter()
            .find_map(|(m, p)| (*p == prefix).then_some(*m))
    }

    /// Whether a char is a known prefix (used to strip `@`/`+` from
    /// names in 353 RPL_NAMREPLY).
    #[must_use]
    pub fn is_prefix(&self, c: char) -> bool {
        self.entries.iter().any(|(_, p)| *p == c)
    }

    /// Whether a mode letter changes a prefix (PREFIX-mode).
    #[must_use]
    pub fn is_prefix_mode(&self, mode: char) -> bool {
        self.entries.iter().any(|(m, _)| *m == mode)
    }
}

// ----- member + channel ----------------------------------------------------

/// One member of a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub nick: String,
    pub user: Option<String>,
    pub host: Option<String>,
    /// Mode letters currently held (e.g. `{'o', 'v'}`). Sorted by `BTreeSet`
    /// so equality / display is stable.
    pub modes: BTreeSet<char>,
}

impl Member {
    fn new(nick: String, user: Option<String>, host: Option<String>) -> Self {
        Self {
            nick,
            user,
            host,
            modes: BTreeSet::new(),
        }
    }
}

/// One IRC channel as observed from this connection.
#[derive(Debug, Clone, Default)]
pub struct ChannelState {
    pub name: String,
    /// Members, keyed by [`irc_lower`] of the nick.
    pub members: BTreeMap<String, Member>,
    pub topic: Option<String>,
    pub topic_set_by: Option<String>,
    pub topic_set_at: Option<i64>,
}

impl ChannelState {
    fn with_name(name: String) -> Self {
        Self {
            name,
            ..Self::default()
        }
    }
}

// ----- server state --------------------------------------------------------

/// Aggregate state for one IRC server connection.
#[derive(Debug, Clone, Default)]
pub struct ServerState {
    /// Our nickname. Set on RPL_WELCOME (001) and updated on self NICK.
    pub my_nick: Option<String>,
    /// Channels we're in, keyed by [`irc_lower`] of the channel name.
    pub channels: BTreeMap<String, ChannelState>,
    /// Mode-prefix mapping (defaults to `(ov)@+` until 005 PREFIX is seen).
    pub prefix_map: PrefixMap,
    /// True once 001 RPL_WELCOME has been received.
    pub registered: bool,
}

impl ServerState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience accessor for channels, case-insensitive.
    #[must_use]
    pub fn channel(&self, name: &str) -> Option<&ChannelState> {
        self.channels.get(&irc_lower(name))
    }

    /// Whether `nick` is us.
    #[must_use]
    pub fn is_self(&self, nick: &str) -> bool {
        self.my_nick
            .as_deref()
            .is_some_and(|me| irc_lower(me) == irc_lower(nick))
    }

    /// Process one parsed message and return the resulting events.
    pub fn process(&mut self, msg: &Message<'_>) -> Vec<StateEvent> {
        // Numerics first.
        if let crate::message::Command::Numeric(n) = msg.command {
            return self.process_numeric(n, msg);
        }

        // Word commands.
        if msg.is_command("PING") {
            if let Some(token) = msg.param(0) {
                return vec![StateEvent::Ping {
                    token: token.to_owned(),
                }];
            }
            return Vec::new();
        }
        if msg.is_command("JOIN") {
            return self.process_join(msg);
        }
        if msg.is_command("PART") {
            return self.process_part(msg);
        }
        if msg.is_command("QUIT") {
            return self.process_quit(msg);
        }
        if msg.is_command("KICK") {
            return self.process_kick(msg);
        }
        if msg.is_command("NICK") {
            return self.process_nick(msg);
        }
        if msg.is_command("MODE") {
            return self.process_mode(msg);
        }
        if msg.is_command("TOPIC") {
            return self.process_topic(msg);
        }
        if msg.is_command("PRIVMSG") {
            return passthrough(msg, |from, target, body| StateEvent::Privmsg {
                from,
                target,
                body,
            });
        }
        if msg.is_command("NOTICE") {
            return passthrough(msg, |from, target, body| StateEvent::Notice {
                from,
                target,
                body,
            });
        }

        Vec::new()
    }

    fn process_numeric(&mut self, n: u16, msg: &Message<'_>) -> Vec<StateEvent> {
        match n {
            1 => {
                // RPL_WELCOME: param[0] is our nickname as the server sees it.
                if let Some(nick) = msg.param(0) {
                    self.my_nick = Some(nick.to_owned());
                }
                self.registered = true;
                vec![StateEvent::Welcomed {
                    nick: msg.param(0).unwrap_or("").to_owned(),
                }]
            }
            5 => {
                // RPL_ISUPPORT: each param past param[0] (our nick) is a
                // KEY[=value] token. We only consume PREFIX for now.
                for token in msg.params.iter().skip(1) {
                    if let Some(value) = token.strip_prefix("PREFIX=") {
                        self.prefix_map = PrefixMap::parse(value);
                    }
                }
                Vec::new()
            }
            332 => {
                // RPL_TOPIC: <client> <chan> :<topic>
                let chan_name = msg.param(1).unwrap_or("");
                let topic = msg.param(2).unwrap_or("").to_owned();
                let chan = self
                    .channels
                    .entry(irc_lower(chan_name))
                    .or_insert_with(|| ChannelState::with_name(chan_name.to_owned()));
                chan.topic = Some(topic.clone());
                vec![StateEvent::TopicSet {
                    channel: chan_name.to_owned(),
                    topic,
                    set_by: None,
                    set_at: None,
                }]
            }
            333 => {
                // RPL_TOPICWHOTIME: <client> <chan> <set_by> <set_at>
                let chan_name = msg.param(1).unwrap_or("");
                let by = msg.param(2).map(str::to_owned);
                let at = msg.param(3).and_then(|s| s.parse().ok());
                if let Some(chan) = self.channels.get_mut(&irc_lower(chan_name)) {
                    chan.topic_set_by.clone_from(&by);
                    chan.topic_set_at = at;
                }
                vec![StateEvent::TopicSet {
                    channel: chan_name.to_owned(),
                    topic: self
                        .channel(chan_name)
                        .and_then(|c| c.topic.clone())
                        .unwrap_or_default(),
                    set_by: by,
                    set_at: at,
                }]
            }
            353 => {
                // RPL_NAMREPLY: <client> <symbol> <chan> :<names>
                // Names may carry one or more prefix chars (multi-prefix cap).
                let chan_name = msg.param(2).unwrap_or("");
                let Some(names_field) = msg.param(3) else {
                    return Vec::new();
                };
                let chan = self
                    .channels
                    .entry(irc_lower(chan_name))
                    .or_insert_with(|| ChannelState::with_name(chan_name.to_owned()));
                for entry in names_field.split(' ').filter(|s| !s.is_empty()) {
                    let mut modes = BTreeSet::new();
                    let mut chars = entry.chars().peekable();
                    while let Some(&c) = chars.peek() {
                        if self.prefix_map.is_prefix(c) {
                            if let Some(m) = self.prefix_map.mode_for_prefix(c) {
                                modes.insert(m);
                            }
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    let nick: String = chars.collect();
                    if nick.is_empty() {
                        continue;
                    }
                    let mut member = Member::new(nick.clone(), None, None);
                    member.modes = modes;
                    chan.members.insert(irc_lower(&nick), member);
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn process_join(&mut self, msg: &Message<'_>) -> Vec<StateEvent> {
        let chan_name = msg.param(0).unwrap_or("");
        let (nick, user, host) = parse_source(msg.source.unwrap_or(""));
        let is_self = self.is_self(&nick);

        let chan = self
            .channels
            .entry(irc_lower(chan_name))
            .or_insert_with(|| ChannelState::with_name(chan_name.to_owned()));
        let member = Member::new(nick.clone(), user, host);
        chan.members.insert(irc_lower(&nick), member.clone());

        vec![StateEvent::Joined {
            channel: chan_name.to_owned(),
            member,
            is_self,
        }]
    }

    fn process_part(&mut self, msg: &Message<'_>) -> Vec<StateEvent> {
        let chan_name = msg.param(0).unwrap_or("");
        let reason = msg.param(1).map(str::to_owned);
        let (nick, _, _) = parse_source(msg.source.unwrap_or(""));
        let is_self = self.is_self(&nick);

        if let Some(chan) = self.channels.get_mut(&irc_lower(chan_name)) {
            chan.members.remove(&irc_lower(&nick));
        }
        if is_self {
            self.channels.remove(&irc_lower(chan_name));
        }

        vec![StateEvent::Parted {
            channel: chan_name.to_owned(),
            nick,
            reason,
            is_self,
        }]
    }

    fn process_quit(&mut self, msg: &Message<'_>) -> Vec<StateEvent> {
        let (nick, _, _) = parse_source(msg.source.unwrap_or(""));
        let reason = msg.param(0).map(str::to_owned);
        for chan in self.channels.values_mut() {
            chan.members.remove(&irc_lower(&nick));
        }
        vec![StateEvent::Quit { nick, reason }]
    }

    fn process_kick(&mut self, msg: &Message<'_>) -> Vec<StateEvent> {
        let chan_name = msg.param(0).unwrap_or("");
        let target = msg.param(1).unwrap_or("").to_owned();
        let reason = msg.param(2).map(str::to_owned);
        let (by, _, _) = parse_source(msg.source.unwrap_or(""));
        let is_self_target = self.is_self(&target);

        if let Some(chan) = self.channels.get_mut(&irc_lower(chan_name)) {
            chan.members.remove(&irc_lower(&target));
        }
        if is_self_target {
            self.channels.remove(&irc_lower(chan_name));
        }

        vec![StateEvent::Kicked {
            channel: chan_name.to_owned(),
            target,
            by,
            reason,
            is_self_target,
        }]
    }

    fn process_nick(&mut self, msg: &Message<'_>) -> Vec<StateEvent> {
        let (old_nick, _, _) = parse_source(msg.source.unwrap_or(""));
        let new_nick = msg.param(0).unwrap_or("").to_owned();
        let is_self = self.is_self(&old_nick);
        if is_self {
            self.my_nick = Some(new_nick.clone());
        }
        // Move membership in every channel.
        for chan in self.channels.values_mut() {
            if let Some(mut member) = chan.members.remove(&irc_lower(&old_nick)) {
                member.nick.clone_from(&new_nick);
                chan.members.insert(irc_lower(&new_nick), member);
            }
        }
        vec![StateEvent::NickChanged {
            old_nick,
            new_nick,
            is_self,
        }]
    }

    fn process_mode(&mut self, msg: &Message<'_>) -> Vec<StateEvent> {
        // MODE <target> <modes> [<args>...]
        let target = msg.param(0).unwrap_or("").to_owned();
        let modes_str = msg.param(1).unwrap_or("");
        let (by, _, _) = parse_source(msg.source.unwrap_or(""));

        // Only apply PREFIX-mode changes to channel members. Non-PREFIX
        // modes (b/e/I/k/l, plus channel toggles like +i/+s/+t/+m/+n) are
        // emitted as a generic ModeChanged event for now; M3 wires them
        // into chanset/masklist storage.
        if target.starts_with('#') || target.starts_with('&') {
            // Channel mode change.
            if let Some(chan) = self.channels.get_mut(&irc_lower(&target)) {
                let mut adding = true;
                let mut arg_idx = 2;
                for c in modes_str.chars() {
                    match c {
                        '+' => adding = true,
                        '-' => adding = false,
                        m if self.prefix_map.is_prefix_mode(m) => {
                            // Pull the next arg (the affected nick).
                            let Some(nick) = msg.param(arg_idx) else {
                                continue;
                            };
                            arg_idx += 1;
                            if let Some(member) = chan.members.get_mut(&irc_lower(nick)) {
                                if adding {
                                    member.modes.insert(m);
                                } else {
                                    member.modes.remove(&m);
                                }
                            }
                        }
                        _ => {
                            // Non-PREFIX mode; some take args, some don't.
                            // Without CHANMODES we don't know which; consume
                            // an arg conservatively for letters that are
                            // commonly arg-bearing (b, e, I, k, l for +k/+l).
                            if matches!(c, 'b' | 'e' | 'I' | 'k' | 'l') {
                                arg_idx += usize::from(msg.param(arg_idx).is_some());
                            }
                        }
                    }
                }
            }
        }

        vec![StateEvent::ModeChanged {
            target,
            by,
            modes: modes_str.to_owned(),
            args: msg.params.iter().skip(2).map(|s| (*s).to_owned()).collect(),
        }]
    }

    fn process_topic(&mut self, msg: &Message<'_>) -> Vec<StateEvent> {
        let chan_name = msg.param(0).unwrap_or("");
        let topic = msg.param(1).unwrap_or("").to_owned();
        let (by, _, _) = parse_source(msg.source.unwrap_or(""));
        if let Some(chan) = self.channels.get_mut(&irc_lower(chan_name)) {
            chan.topic = Some(topic.clone());
            chan.topic_set_by = Some(by.clone());
        }
        vec![StateEvent::TopicSet {
            channel: chan_name.to_owned(),
            topic,
            set_by: Some(by),
            set_at: None,
        }]
    }
}

fn passthrough<F>(msg: &Message<'_>, build: F) -> Vec<StateEvent>
where
    F: FnOnce(Option<String>, String, String) -> StateEvent,
{
    let target = msg.param(0).unwrap_or("").to_owned();
    let body = msg.param(1).unwrap_or("").to_owned();
    let from = msg.source.map(str::to_owned);
    vec![build(from, target, body)]
}

// ----- events --------------------------------------------------------------

/// High-level events emitted by [`ServerState::process`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateEvent {
    /// Server sent 001 RPL_WELCOME; registration is complete.
    Welcomed { nick: String },
    /// A client joined a channel (us if `is_self`).
    Joined {
        channel: String,
        member: Member,
        is_self: bool,
    },
    /// A client parted a channel.
    Parted {
        channel: String,
        nick: String,
        reason: Option<String>,
        is_self: bool,
    },
    /// A client was kicked.
    Kicked {
        channel: String,
        target: String,
        by: String,
        reason: Option<String>,
        is_self_target: bool,
    },
    /// A client changed nicks. Affects all channels they share with us.
    NickChanged {
        old_nick: String,
        new_nick: String,
        is_self: bool,
    },
    /// A client quit; removes them from all our tracked channels.
    Quit {
        nick: String,
        reason: Option<String>,
    },
    /// Topic state for a channel changed (via 332/333 numerics or TOPIC).
    TopicSet {
        channel: String,
        topic: String,
        set_by: Option<String>,
        set_at: Option<i64>,
    },
    /// Channel or user modes changed. PREFIX-mode changes are applied to
    /// member state internally; this event also fires so consumers can
    /// react (logging, audit, etc.).
    ModeChanged {
        target: String,
        by: String,
        modes: String,
        args: Vec<String>,
    },
    /// A PRIVMSG was received.
    Privmsg {
        from: Option<String>,
        target: String,
        body: String,
    },
    /// A NOTICE was received.
    Notice {
        from: Option<String>,
        target: String,
        body: String,
    },
    /// Server PING; the consumer should respond with PONG <token>.
    Ping { token: String },
}

// ----- helpers -------------------------------------------------------------

/// Lowercase an IRC name. ASCII-only for MVP; full RFC1459 mapping
/// (`[]\^` ↔ `{}|~`) ships when we hit a network that needs it.
#[must_use]
pub fn irc_lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Parse a source string into `(nick, user, host)`. Server sources without
/// `!` are returned with `nick = source`, `user = None`, `host = None`.
fn parse_source(source: &str) -> (String, Option<String>, Option<String>) {
    if let Some((nick_user, host)) = source.split_once('@') {
        if let Some((nick, user)) = nick_user.split_once('!') {
            return (
                nick.to_owned(),
                Some(user.to_owned()),
                Some(host.to_owned()),
            );
        }
        return (nick_user.to_owned(), None, Some(host.to_owned()));
    }
    (source.to_owned(), None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_str;

    fn process(state: &mut ServerState, line: &str) -> Vec<StateEvent> {
        let msg = parse_str(line).unwrap();
        state.process(&msg)
    }

    #[test]
    fn prefix_map_default_is_ov() {
        let p = PrefixMap::default();
        assert_eq!(p.mode_for_prefix('@'), Some('o'));
        assert_eq!(p.mode_for_prefix('+'), Some('v'));
        assert_eq!(p.mode_for_prefix('%'), None);
    }

    #[test]
    fn prefix_map_parses_ohv() {
        let p = PrefixMap::parse("(ohv)@%+");
        assert_eq!(p.mode_for_prefix('@'), Some('o'));
        assert_eq!(p.mode_for_prefix('%'), Some('h'));
        assert_eq!(p.mode_for_prefix('+'), Some('v'));
    }

    #[test]
    fn prefix_map_malformed_falls_back_to_default() {
        let p = PrefixMap::parse("garbage");
        assert_eq!(p, PrefixMap::default());
    }

    #[test]
    fn welcomed_sets_my_nick_and_registered() {
        let mut s = ServerState::new();
        let events = process(&mut s, ":server 001 shade :Welcome");
        assert_eq!(
            events,
            vec![StateEvent::Welcomed {
                nick: "shade".into()
            }]
        );
        assert_eq!(s.my_nick.as_deref(), Some("shade"));
        assert!(s.registered);
    }

    #[test]
    fn isupport_prefix_token_updates_prefix_map() {
        let mut s = ServerState::new();
        let _ = process(&mut s, ":server 005 shade PREFIX=(ohv)@%+ :are supported");
        assert_eq!(s.prefix_map.mode_for_prefix('%'), Some('h'));
    }

    #[test]
    fn join_adds_member() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let events = process(&mut s, ":alice!u@h JOIN #c");
        assert_eq!(events.len(), 1);
        let chan = s.channel("#c").unwrap();
        assert_eq!(chan.members.len(), 1);
        let alice = chan.members.get("alice").unwrap();
        assert_eq!(alice.nick, "alice");
        assert_eq!(alice.user.as_deref(), Some("u"));
        assert_eq!(alice.host.as_deref(), Some("h"));
    }

    #[test]
    fn join_self_marks_is_self() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let events = process(&mut s, ":shade!u@h JOIN #c");
        match &events[0] {
            StateEvent::Joined { is_self, .. } => assert!(*is_self),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn part_removes_member() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let _ = process(&mut s, ":alice!u@h JOIN #c");
        let _ = process(&mut s, ":alice!u@h PART #c :leaving");
        assert!(s.channel("#c").unwrap().members.is_empty());
    }

    #[test]
    fn part_self_drops_channel() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let _ = process(&mut s, ":shade!u@h JOIN #c");
        let _ = process(&mut s, ":shade!u@h PART #c");
        assert!(s.channel("#c").is_none());
    }

    #[test]
    fn quit_removes_from_all_channels() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let _ = process(&mut s, ":alice!u@h JOIN #a");
        let _ = process(&mut s, ":alice!u@h JOIN #b");
        let events = process(&mut s, ":alice!u@h QUIT :bye");
        assert_eq!(
            events,
            vec![StateEvent::Quit {
                nick: "alice".into(),
                reason: Some("bye".into())
            }]
        );
        assert!(s.channel("#a").unwrap().members.is_empty());
        assert!(s.channel("#b").unwrap().members.is_empty());
    }

    #[test]
    fn kick_removes_target() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let _ = process(&mut s, ":alice!u@h JOIN #c");
        let _ = process(&mut s, ":bob!u@h KICK #c alice :bad");
        assert!(s.channel("#c").unwrap().members.is_empty());
    }

    #[test]
    fn kick_self_drops_channel() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let _ = process(&mut s, ":shade!u@h JOIN #c");
        let _ = process(&mut s, ":enemy!u@h KICK #c shade :rude");
        assert!(s.channel("#c").is_none());
    }

    #[test]
    fn nick_change_updates_membership_and_self() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let _ = process(&mut s, ":shade!u@h JOIN #c");
        let _ = process(&mut s, ":alice!u@h JOIN #c");
        let _ = process(&mut s, ":alice!u@h NICK alice2");
        let chan = s.channel("#c").unwrap();
        assert!(!chan.members.contains_key("alice"));
        assert!(chan.members.contains_key("alice2"));

        // Self nick change.
        let _ = process(&mut s, ":shade!u@h NICK shade2");
        assert_eq!(s.my_nick.as_deref(), Some("shade2"));
        let chan = s.channel("#c").unwrap();
        assert!(chan.members.contains_key("shade2"));
    }

    #[test]
    fn namreply_with_multi_prefix_assigns_modes() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let _ = process(&mut s, ":server 353 shade = #c :@+alice +bob plain");
        let chan = s.channel("#c").unwrap();
        let alice = chan.members.get("alice").unwrap();
        assert!(alice.modes.contains(&'o'));
        assert!(alice.modes.contains(&'v'));
        let bob = chan.members.get("bob").unwrap();
        assert!(bob.modes.contains(&'v'));
        assert!(!bob.modes.contains(&'o'));
        let plain = chan.members.get("plain").unwrap();
        assert!(plain.modes.is_empty());
    }

    #[test]
    fn topic_numerics_populate_channel_state() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let _ = process(&mut s, ":server 332 shade #c :Hello world");
        let _ = process(&mut s, ":server 333 shade #c alice 1700000000");
        let chan = s.channel("#c").unwrap();
        assert_eq!(chan.topic.as_deref(), Some("Hello world"));
        assert_eq!(chan.topic_set_by.as_deref(), Some("alice"));
        assert_eq!(chan.topic_set_at, Some(1_700_000_000));
    }

    #[test]
    fn topic_command_updates_state() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let _ = process(&mut s, ":alice!u@h JOIN #c");
        let _ = process(&mut s, ":alice!u@h TOPIC #c :new topic");
        assert_eq!(s.channel("#c").unwrap().topic.as_deref(), Some("new topic"));
    }

    #[test]
    fn mode_op_then_deop() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let _ = process(&mut s, ":alice!u@h JOIN #c");
        let _ = process(&mut s, ":bob!u@h MODE #c +o alice");
        assert!(s
            .channel("#c")
            .unwrap()
            .members
            .get("alice")
            .unwrap()
            .modes
            .contains(&'o'));
        let _ = process(&mut s, ":bob!u@h MODE #c -o alice");
        assert!(!s
            .channel("#c")
            .unwrap()
            .members
            .get("alice")
            .unwrap()
            .modes
            .contains(&'o'));
    }

    #[test]
    fn mode_combined_op_voice_in_one_command() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let _ = process(&mut s, ":alice!u@h JOIN #c");
        let _ = process(&mut s, ":bob!u@h JOIN #c");
        let _ = process(&mut s, ":op!u@h MODE #c +ov alice bob");
        assert!(s
            .channel("#c")
            .unwrap()
            .members
            .get("alice")
            .unwrap()
            .modes
            .contains(&'o'));
        assert!(s
            .channel("#c")
            .unwrap()
            .members
            .get("bob")
            .unwrap()
            .modes
            .contains(&'v'));
    }

    #[test]
    fn ping_emits_event_with_token() {
        let mut s = ServerState::new();
        let events = process(&mut s, "PING :server.example");
        assert_eq!(
            events,
            vec![StateEvent::Ping {
                token: "server.example".into()
            }]
        );
    }

    #[test]
    fn privmsg_passthrough() {
        let mut s = ServerState::new();
        let events = process(&mut s, ":alice!u@h PRIVMSG #c :hello");
        assert_eq!(
            events,
            vec![StateEvent::Privmsg {
                from: Some("alice!u@h".into()),
                target: "#c".into(),
                body: "hello".into(),
            }]
        );
    }

    #[test]
    fn case_insensitive_channel_lookup() {
        let mut s = ServerState::new();
        s.my_nick = Some("shade".into());
        let _ = process(&mut s, ":alice!u@h JOIN #FoO");
        assert!(s.channel("#foo").is_some());
        assert!(s.channel("#FOO").is_some());
        assert!(s.channel("#bar").is_none());
    }

    #[test]
    fn parse_source_handles_server_and_user() {
        assert_eq!(
            parse_source("nick!user@host"),
            ("nick".into(), Some("user".into()), Some("host".into()))
        );
        assert_eq!(
            parse_source("server.example.org"),
            ("server.example.org".into(), None, None)
        );
        assert_eq!(
            parse_source("nick@host"),
            ("nick".into(), None, Some("host".into()))
        );
    }
}
