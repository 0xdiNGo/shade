//! Shared shutdown signal for daemon tasks.
//!
//! `run()` builds a single [`ShutdownSignal`] at startup and clones it
//! into every long-running task (admin listener, metrics listener, IRC
//! session, etc.). When Ctrl-C / SIGTERM arrives, `run()` calls
//! [`ShutdownSignal::trigger`]; every consumer awaiting
//! [`ShutdownSignal::recv`] then resolves and gets to drain its
//! in-flight work cleanly before exiting.
//!
//! Implementation is a `tokio::sync::watch::channel(false)` with a
//! semantic of "watch transitions from `false` to `true`." Receivers
//! are cheap to clone; a single sender lives in the daemon's main
//! function.

use tokio::sync::watch;

/// Sender half of the shutdown signal. Held by `run()`; calling
/// [`Self::trigger`] flips the value and wakes every receiver.
#[derive(Debug)]
pub struct Shutdown {
    tx: watch::Sender<bool>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (tx, _) = watch::channel(false);
        Self { tx }
    }

    /// Returns a fresh receiver clone for one consumer.
    #[must_use]
    pub fn signal(&self) -> ShutdownSignal {
        ShutdownSignal {
            rx: self.tx.subscribe(),
        }
    }

    /// Broadcast `true` to every receiver. Idempotent.
    pub fn trigger(&self) {
        // `send` only errors when there are zero receivers, which is
        // fine — at that point nobody is waiting.
        let _ = self.tx.send(true);
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// Receiver half. Clone freely; each task holds its own.
#[derive(Clone, Debug)]
pub struct ShutdownSignal {
    rx: watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Resolves once shutdown has been triggered. Owns the receiver
    /// because `axum::serve(...).with_graceful_shutdown(future)` takes
    /// `future` by value and most consumers want a future, not a
    /// reusable handle.
    pub async fn recv(mut self) {
        // `wait_for` returns once the predicate is true. If the sender
        // is dropped first the receiver also resolves — same effect.
        let _ = self.rx.wait_for(|v| *v).await;
    }

    /// Borrowing variant for callers that need to re-await on the same
    /// receiver across loop iterations.
    pub async fn recv_ref(&mut self) {
        let _ = self.rx.wait_for(|v| *v).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn signal_resolves_after_trigger() {
        let s = Shutdown::new();
        let sig = s.signal();
        let task = tokio::spawn(async move {
            sig.recv().await;
            "done"
        });
        // Without trigger, the task is pending.
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!task.is_finished());

        s.trigger();
        let out = task.await.unwrap();
        assert_eq!(out, "done");
    }

    #[tokio::test]
    async fn trigger_is_idempotent() {
        let s = Shutdown::new();
        let sig = s.signal();
        s.trigger();
        s.trigger();
        sig.recv().await; // resolves immediately on a second call
    }

    #[tokio::test]
    async fn multiple_consumers_all_resolve() {
        let s = Shutdown::new();
        let mut handles = Vec::new();
        for _ in 0..5 {
            let sig = s.signal();
            handles.push(tokio::spawn(async move { sig.recv().await }));
        }
        s.trigger();
        for h in handles {
            h.await.unwrap();
        }
    }

    #[tokio::test]
    async fn signal_resolves_when_sender_drops() {
        // If the daemon panics the Shutdown is dropped without a
        // trigger; receivers should still wake so spawned tasks don't
        // hang forever.
        let s = Shutdown::new();
        let sig = s.signal();
        drop(s);
        sig.recv().await;
    }
}
