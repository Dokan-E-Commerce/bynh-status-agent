//! Exponential backoff with jitter for platform requests (429 and 5xx).

use std::time::Duration;

/// `Retry-After` values above this are capped, so a bad header can't park the
/// agent for days.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    attempt: u32,
}

impl Default for Backoff {
    /// The protocol's 1 s → 5 min.
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(300))
    }
}

impl Backoff {
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap: cap.max(base),
            attempt: 0,
        }
    }

    /// The un-jittered delay for the current attempt: base × 2^attempt, capped.
    pub fn ceiling(&self) -> Duration {
        let factor = 1u32.checked_shl(self.attempt.min(30)).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.cap)
    }

    /// Delay before the next retry. "Equal jitter": half the ceiling plus a
    /// random share of the other half. A `Retry-After` from the server is a
    /// floor (capped at [`MAX_RETRY_AFTER`]).
    pub fn next_delay(&mut self, retry_after: Option<Duration>) -> Duration {
        let ceiling = self.ceiling();
        self.attempt = self.attempt.saturating_add(1);
        let half = ceiling / 2;
        let jitter_ms = fastrand::u64(0..=u64::try_from(half.as_millis()).unwrap_or(u64::MAX));
        let delay = half + Duration::from_millis(jitter_ms);
        match retry_after {
            Some(ra) => delay.max(ra.min(MAX_RETRY_AFTER)),
            None => delay,
        }
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_exponentially_with_cap() {
        let mut b = Backoff::default();
        let mut expected = Duration::from_secs(1);
        for _ in 0..20 {
            assert_eq!(b.ceiling(), expected.min(Duration::from_secs(300)));
            let d = b.next_delay(None);
            let ceil = expected.min(Duration::from_secs(300));
            assert!(
                d >= ceil / 2 && d <= ceil,
                "{d:?} not in [{:?}, {ceil:?}]",
                ceil / 2
            );
            expected *= 2;
        }
        assert_eq!(b.ceiling(), Duration::from_secs(300));
    }

    #[test]
    fn retry_after_is_a_floor() {
        let mut b = Backoff::default();
        assert_eq!(
            b.next_delay(Some(Duration::from_secs(42))),
            Duration::from_secs(42)
        );
        assert_eq!(
            b.next_delay(Some(Duration::from_secs(86_400))),
            MAX_RETRY_AFTER
        );
    }

    #[test]
    fn reset_starts_over() {
        let mut b = Backoff::default();
        for _ in 0..5 {
            b.next_delay(None);
        }
        b.reset();
        assert_eq!(b.attempt(), 0);
        assert!(b.next_delay(None) <= Duration::from_secs(1));
    }

    #[test]
    fn many_attempts_do_not_overflow() {
        let mut b = Backoff::default();
        for _ in 0..1000 {
            assert!(b.next_delay(None) <= Duration::from_secs(300));
        }
    }
}
