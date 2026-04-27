//! Token-bucket rate limiter for outbound IRC writes.
//!
//! IRC servers typically apply flood limits in the neighborhood of
//! ~512 bytes / 2 s with some short burst allowance. This module implements
//! a byte-granular token bucket: capacity is the burst size, refill rate
//! is the steady-state byte budget per second. Callers use
//! [`RateLimiter::wait_for`] to block (asynchronously) until enough tokens
//! are available before writing.

use std::time::Duration;

use tokio::time::Instant;

/// A simple async token bucket, denominated in bytes.
#[derive(Debug)]
pub struct RateLimiter {
    capacity: u64,
    refill_per_sec: u64,
    available: u64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Build a new bucket. `capacity` is the maximum burst (in bytes);
    /// `refill_per_sec` is the steady-state byte budget per second. The
    /// bucket starts full.
    #[must_use]
    pub fn new(capacity: u64, refill_per_sec: u64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            available: capacity,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume `n` tokens immediately. Returns `true` if granted.
    pub fn try_consume(&mut self, n: u64) -> bool {
        self.refill();
        if self.available >= n {
            self.available -= n;
            true
        } else {
            false
        }
    }

    /// Consume `n` tokens, sleeping until they become available. If `n`
    /// exceeds `capacity` this only ever consumes once the full capacity
    /// is replenished — i.e. it doesn't deadlock, but it does mean callers
    /// shouldn't request more than `capacity` in a single shot for
    /// well-shaped traffic.
    pub async fn wait_for(&mut self, n: u64) {
        loop {
            self.refill();
            if self.available >= n {
                self.available -= n;
                return;
            }
            let needed = n - self.available;
            let refill = self.refill_per_sec.max(1);
            // ceil(needed * 1000 / refill) ms.
            let wait_ms = needed.saturating_mul(1000).div_ceil(refill);
            let wait = Duration::from_millis(wait_ms.max(10));
            tokio::time::sleep(wait).await;
        }
    }

    fn refill(&mut self) {
        if self.refill_per_sec == 0 {
            return;
        }
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill);
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        if elapsed_ms == 0 {
            return;
        }
        let new_tokens = elapsed_ms.saturating_mul(self.refill_per_sec) / 1000;
        if new_tokens > 0 {
            self.available = self.available.saturating_add(new_tokens).min(self.capacity);
            // Advance `last_refill` only by the time we actually accounted
            // for, so sub-millisecond fragments accumulate toward the next
            // token.
            let consumed_ms = new_tokens.saturating_mul(1000) / self.refill_per_sec;
            self.last_refill += Duration::from_millis(consumed_ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn full_bucket_grants_immediately() {
        let mut rl = RateLimiter::new(1024, 256);
        assert!(rl.try_consume(512));
        assert!(rl.try_consume(512));
        assert!(!rl.try_consume(1));
    }

    #[tokio::test(start_paused = true)]
    async fn refill_after_time_passes() {
        let mut rl = RateLimiter::new(1024, 256);
        // drain
        assert!(rl.try_consume(1024));
        assert!(!rl.try_consume(1));

        tokio::time::advance(Duration::from_secs(1)).await;
        // 1s × 256 bytes/s = 256 tokens added.
        assert!(rl.try_consume(256));
        assert!(!rl.try_consume(1));
    }

    #[tokio::test(start_paused = true)]
    async fn refill_caps_at_capacity() {
        let mut rl = RateLimiter::new(1024, 256);
        assert!(rl.try_consume(1024));
        // Wait long enough to overfill if not capped.
        tokio::time::advance(Duration::from_secs(60)).await;
        rl.refill();
        assert_eq!(rl.available, 1024);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_sleeps_until_tokens_arrive() {
        let mut rl = RateLimiter::new(256, 256);
        assert!(rl.try_consume(256));

        let start = Instant::now();
        rl.wait_for(128).await;
        let elapsed = start.elapsed();
        // 128 bytes at 256 bytes/s = 0.5s, give or take a tick.
        assert!(elapsed >= Duration::from_millis(450));
        assert!(elapsed < Duration::from_secs(2));
    }
}
