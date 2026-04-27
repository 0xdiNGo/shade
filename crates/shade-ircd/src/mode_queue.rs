//! Outbound MODE batcher.
//!
//! Semantic port of Wraith's `src/mod/irc.mod/mode.cc` flush logic. Modes
//! are accumulated per channel and flushed in batches of up to
//! [`MAX_MODES_PER_LINE`] per outbound `MODE` line. Within a batch:
//!
//! - **Negative modes are emitted first**, then positive — same as Wraith,
//!   same as nearly every IRCD's mode-handling expectation. This avoids a
//!   transient "mode is set then unset" oscillation visible to observers.
//! - **Two parallel queues per channel**: `Standard` for ordinary mode
//!   changes, `Cookie` for op/deop carrying a synthetic ban-mask cookie.
//!   The cookie queue lets the upper layer guarantee an op-with-cookie is
//!   emitted as a single self-contained `+o-b nick !salt@cookie` line and
//!   not interleaved with unrelated mode changes. Cookie generation
//!   itself is an M5 concern; the queue is ready for it.
//! - **Priority preemption**: a [`Priority::Quick`] enqueue causes the
//!   target queue to be returned by [`ModeQueue::poll_due`] immediately on
//!   the next call, regardless of whether the periodic-flush deadline has
//!   elapsed.
//!
//! This module is sync and free of timer machinery; the async runner (the
//! session loop, PR #7) calls [`ModeQueue::poll_due`] on a 250ms tick and
//! after each enqueue, and writes any returned mode lines through the
//! connection writer.
//!
//! The queue does **not** know which modes take arguments and which don't;
//! callers attach an `arg` to the `ModeChange` if and only if the mode
//! takes one. The queue serializes them in the same order they were
//! enqueued (after the neg-before-pos reorder).

use std::collections::BTreeMap;

/// Maximum modes per outbound `MODE` line. RFC1459 says servers must
/// accept at least 3; Wraith hard-codes 6 and that's what every modern
/// IRCD handles cleanly. We follow Wraith.
pub const MAX_MODES_PER_LINE: usize = 6;

/// Which queue a change belongs to.
///
/// `Cookie` changes are kept apart from `Standard` ones so the
/// op-with-cookie handshake is emitted atomically per line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QueueKind {
    Standard,
    Cookie,
}

/// Priority a mode change carries.
///
/// `Normal` modes are flushed on the next periodic tick; `Quick` modes
/// trigger an immediate flush on the next `poll_due` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Normal,
    Quick,
}

/// `+` (add) vs `-` (remove).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Add,
    Remove,
}

impl Direction {
    fn as_char(self) -> char {
        match self {
            Self::Add => '+',
            Self::Remove => '-',
        }
    }
}

/// One queued mode change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeChange {
    pub direction: Direction,
    pub mode: char,
    pub arg: Option<String>,
    pub priority: Priority,
}

impl ModeChange {
    /// Build a `+mode` change with an optional argument.
    #[must_use]
    pub fn add(mode: char, arg: Option<String>) -> Self {
        Self {
            direction: Direction::Add,
            mode,
            arg,
            priority: Priority::Normal,
        }
    }

    /// Build a `-mode` change with an optional argument.
    #[must_use]
    pub fn remove(mode: char, arg: Option<String>) -> Self {
        Self {
            direction: Direction::Remove,
            mode,
            arg,
            priority: Priority::Normal,
        }
    }

    /// Mark the change as `Quick` priority. Returns self for chaining.
    #[must_use]
    pub fn with_quick_priority(mut self) -> Self {
        self.priority = Priority::Quick;
        self
    }
}

/// Per-channel, per-kind pending changes.
type Bucket = Vec<ModeChange>;

/// Batched mode-change queue.
///
/// Construct with [`ModeQueue::new`], enqueue with [`ModeQueue::enqueue`],
/// and call [`ModeQueue::poll_due`] periodically (and after each enqueue,
/// for `Quick`-priority preemption) to retrieve outbound MODE lines.
#[derive(Debug, Default)]
pub struct ModeQueue {
    buckets: BTreeMap<(String, QueueKind), Bucket>,
}

impl ModeQueue {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue a single mode change for `channel` in the named queue.
    pub fn enqueue(&mut self, channel: &str, kind: QueueKind, change: ModeChange) {
        self.buckets
            .entry((channel.to_owned(), kind))
            .or_default()
            .push(change);
    }

    /// Number of pending changes in one bucket.
    #[must_use]
    pub fn pending(&self, channel: &str, kind: QueueKind) -> usize {
        self.buckets
            .get(&(channel.to_owned(), kind))
            .map_or(0, Vec::len)
    }

    /// Drain all pending changes for `(channel, kind)` and serialize them
    /// as one or more outbound `MODE` lines. Returns an empty `Vec` if
    /// the bucket has no pending changes.
    pub fn flush(&mut self, channel: &str, kind: QueueKind) -> Vec<String> {
        let Some(bucket) = self.buckets.remove(&(channel.to_owned(), kind)) else {
            return Vec::new();
        };
        serialize_lines(channel, &bucket)
    }

    /// Examine all buckets and return the lines that should be sent right
    /// now: any bucket holding a `Quick`-priority change, *or* (under the
    /// caller's policy) all buckets when called on a periodic tick.
    ///
    /// The `flush_all_buckets` flag distinguishes the two callers:
    /// - The 250ms tick passes `true` → flush every non-empty bucket.
    /// - Post-enqueue calls pass `false` → flush only buckets with at
    ///   least one `Quick`-priority change, or buckets whose size has hit
    ///   the per-line cap (so we don't sit on a full batch).
    pub fn poll_due(&mut self, flush_all_buckets: bool) -> Vec<(String, String)> {
        // Identify keys to flush before mutating, to satisfy the borrow
        // checker.
        let to_flush: Vec<(String, QueueKind)> = self
            .buckets
            .iter()
            .filter(|(_, bucket)| {
                if flush_all_buckets {
                    return !bucket.is_empty();
                }
                bucket.iter().any(|c| c.priority == Priority::Quick)
                    || bucket.len() >= MAX_MODES_PER_LINE
            })
            .map(|((chan, kind), _)| (chan.clone(), *kind))
            .collect();

        let mut out = Vec::new();
        for (chan, kind) in to_flush {
            for line in self.flush(&chan, kind) {
                out.push((chan.clone(), line));
            }
        }
        out
    }
}

/// Serialize a non-empty list of mode changes for `channel` into one or
/// more `MODE` lines, respecting:
/// - Removes before adds (within each line).
/// - At most [`MAX_MODES_PER_LINE`] modes per line.
/// - Args appended in the same order as the mode chars.
fn serialize_lines(channel: &str, changes: &[ModeChange]) -> Vec<String> {
    if changes.is_empty() {
        return Vec::new();
    }

    // Reorder: removes first, then adds, preserving insertion order
    // within each direction.
    let mut ordered: Vec<&ModeChange> = changes
        .iter()
        .filter(|c| matches!(c.direction, Direction::Remove))
        .collect();
    ordered.extend(
        changes
            .iter()
            .filter(|c| matches!(c.direction, Direction::Add)),
    );

    let mut lines = Vec::new();
    for chunk in ordered.chunks(MAX_MODES_PER_LINE) {
        lines.push(format_one_line(channel, chunk));
    }
    lines
}

fn format_one_line(channel: &str, chunk: &[&ModeChange]) -> String {
    let mut mode_str = String::new();
    let mut args: Vec<&str> = Vec::new();
    let mut last_dir: Option<Direction> = None;

    for ch in chunk {
        if last_dir != Some(ch.direction) {
            mode_str.push(ch.direction.as_char());
            last_dir = Some(ch.direction);
        }
        mode_str.push(ch.mode);
        if let Some(arg) = ch.arg.as_deref() {
            args.push(arg);
        }
    }

    if args.is_empty() {
        format!("MODE {channel} {mode_str}")
    } else {
        format!("MODE {channel} {mode_str} {}", args.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(nick: &str) -> ModeChange {
        ModeChange::add('o', Some(nick.to_owned()))
    }
    fn deop(nick: &str) -> ModeChange {
        ModeChange::remove('o', Some(nick.to_owned()))
    }
    fn voice(nick: &str) -> ModeChange {
        ModeChange::add('v', Some(nick.to_owned()))
    }

    #[test]
    fn empty_queue_flushes_nothing() {
        let mut q = ModeQueue::new();
        assert!(q.flush("#c", QueueKind::Standard).is_empty());
    }

    #[test]
    fn single_op_flushes_one_line() {
        let mut q = ModeQueue::new();
        q.enqueue("#c", QueueKind::Standard, op("alice"));
        let lines = q.flush("#c", QueueKind::Standard);
        assert_eq!(lines, vec!["MODE #c +o alice"]);
    }

    #[test]
    fn negatives_emitted_before_positives() {
        let mut q = ModeQueue::new();
        // Enqueue in mixed order; flush should reorder.
        q.enqueue("#c", QueueKind::Standard, op("alice"));
        q.enqueue("#c", QueueKind::Standard, deop("bob"));
        q.enqueue("#c", QueueKind::Standard, voice("carol"));
        let lines = q.flush("#c", QueueKind::Standard);
        assert_eq!(lines, vec!["MODE #c -o+ov bob alice carol"]);
    }

    #[test]
    fn six_modes_pack_into_one_line() {
        let mut q = ModeQueue::new();
        for nick in ["a", "b", "c", "d", "e", "f"] {
            q.enqueue("#c", QueueKind::Standard, op(nick));
        }
        let lines = q.flush("#c", QueueKind::Standard);
        assert_eq!(lines, vec!["MODE #c +oooooo a b c d e f"]);
    }

    #[test]
    fn seven_modes_split_into_two_lines() {
        let mut q = ModeQueue::new();
        for nick in ["a", "b", "c", "d", "e", "f", "g"] {
            q.enqueue("#c", QueueKind::Standard, op(nick));
        }
        let lines = q.flush("#c", QueueKind::Standard);
        assert_eq!(lines, vec!["MODE #c +oooooo a b c d e f", "MODE #c +o g"]);
    }

    #[test]
    fn modes_without_args_omit_the_args_field() {
        let mut q = ModeQueue::new();
        q.enqueue("#c", QueueKind::Standard, ModeChange::add('i', None));
        q.enqueue("#c", QueueKind::Standard, ModeChange::remove('m', None));
        let lines = q.flush("#c", QueueKind::Standard);
        assert_eq!(lines, vec!["MODE #c -m+i"]);
    }

    #[test]
    fn cookie_queue_is_independent() {
        let mut q = ModeQueue::new();
        q.enqueue("#c", QueueKind::Standard, voice("alice"));
        q.enqueue("#c", QueueKind::Cookie, op("alice"));
        let standard = q.flush("#c", QueueKind::Standard);
        let cookie = q.flush("#c", QueueKind::Cookie);
        assert_eq!(standard, vec!["MODE #c +v alice"]);
        assert_eq!(cookie, vec!["MODE #c +o alice"]);
    }

    #[test]
    fn poll_due_with_flush_all_returns_every_bucket() {
        let mut q = ModeQueue::new();
        q.enqueue("#a", QueueKind::Standard, op("alice"));
        q.enqueue("#b", QueueKind::Standard, deop("bob"));
        let mut out = q.poll_due(true);
        out.sort();
        assert_eq!(
            out,
            vec![
                ("#a".to_string(), "MODE #a +o alice".to_string()),
                ("#b".to_string(), "MODE #b -o bob".to_string()),
            ]
        );
        // Buckets emptied.
        assert_eq!(q.pending("#a", QueueKind::Standard), 0);
        assert_eq!(q.pending("#b", QueueKind::Standard), 0);
    }

    #[test]
    fn poll_due_without_flush_all_holds_normal_priority() {
        let mut q = ModeQueue::new();
        q.enqueue("#c", QueueKind::Standard, op("alice"));
        let out = q.poll_due(false);
        assert!(out.is_empty(), "normal priority shouldn't preempt");
        assert_eq!(q.pending("#c", QueueKind::Standard), 1);
    }

    #[test]
    fn quick_priority_preempts_via_poll_due() {
        let mut q = ModeQueue::new();
        q.enqueue("#c", QueueKind::Standard, op("alice").with_quick_priority());
        let out = q.poll_due(false);
        assert_eq!(
            out,
            vec![("#c".to_string(), "MODE #c +o alice".to_string())]
        );
        assert_eq!(q.pending("#c", QueueKind::Standard), 0);
    }

    #[test]
    fn full_bucket_flushes_via_poll_due_without_flush_all() {
        let mut q = ModeQueue::new();
        for nick in ["a", "b", "c", "d", "e", "f"] {
            q.enqueue("#c", QueueKind::Standard, op(nick));
        }
        let out = q.poll_due(false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].1, "MODE #c +oooooo a b c d e f");
    }

    #[test]
    fn full_bucket_plus_extra_emits_two_lines_on_full_flush() {
        let mut q = ModeQueue::new();
        for nick in ["a", "b", "c", "d", "e", "f", "g"] {
            q.enqueue("#c", QueueKind::Standard, op(nick));
        }
        let out = q.poll_due(true);
        assert_eq!(out.len(), 2);
    }
}
