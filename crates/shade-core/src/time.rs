//! Time helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current wall-clock time as Unix milliseconds.
///
/// Used by every `*Upsert` path that stamps `updated_at`. Falls back to
/// `0` if the system clock is somehow before the Unix epoch — a real
/// clock-step backwards is the operator's problem; the LWW gossip will
/// just look like every node is producing zero-timestamped writes until
/// the clock recovers.
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_ms_is_positive_and_above_2025_epoch() {
        // 2025-01-01 in ms.
        let lower = 1_735_689_600_000_i64;
        let now = now_ms();
        assert!(
            now > lower,
            "now_ms()={now} is below the 2025 epoch — clock is wrong",
        );
    }
}
