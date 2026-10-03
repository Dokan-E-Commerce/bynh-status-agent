//! Bounded in-memory buffer of unsent results. When full, the oldest result
//! is dropped and counted.

use std::collections::VecDeque;
use std::sync::Mutex;

use crate::protocol::CheckResult;

/// Protocol limit on buffered results.
pub const DEFAULT_CAPACITY: usize = 10_000;

pub struct ResultBuffer {
    inner: Mutex<Inner>,
}

struct Inner {
    queue: VecDeque<(u64, CheckResult)>,
    capacity: usize,
    next_seq: u64,
    dropped_total: u64,
    dropped_unreported: u64,
}

/// A batch peeked from the buffer. Results stay buffered until [`ResultBuffer::ack`].
pub struct Batch {
    pub results: Vec<CheckResult>,
    last_seq: u64,
}

impl Default for ResultBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl ResultBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                queue: VecDeque::new(),
                capacity: capacity.max(1),
                next_seq: 0,
                dropped_total: 0,
                dropped_unreported: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding this lock can't leave the queue inconsistent.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn push(&self, result: CheckResult) {
        let mut g = self.lock();
        while g.queue.len() >= g.capacity {
            g.queue.pop_front();
            g.dropped_total += 1;
            g.dropped_unreported += 1;
        }
        let seq = g.next_seq;
        g.next_seq += 1;
        g.queue.push_back((seq, result));
    }

    /// Copies up to `max` of the oldest results without removing them, so a
    /// request that fails or is cancelled loses nothing.
    pub fn peek(&self, max: usize) -> Option<Batch> {
        let g = self.lock();
        if g.queue.is_empty() || max == 0 {
            return None;
        }
        let mut results = Vec::with_capacity(max.min(g.queue.len()));
        let mut last_seq = 0;
        for (seq, r) in g.queue.iter().take(max) {
            results.push(r.clone());
            last_seq = *seq;
        }
        Some(Batch { results, last_seq })
    }

    /// Removes the results of a delivered batch. Safe even if some of them
    /// were already dropped for space in the meantime.
    pub fn ack(&self, batch: &Batch) {
        let mut g = self.lock();
        while g
            .queue
            .front()
            .is_some_and(|(seq, _)| *seq <= batch.last_seq)
        {
            g.queue.pop_front();
        }
    }

    pub fn len(&self) -> usize {
        self.lock().queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn dropped_total(&self) -> u64 {
        self.lock().dropped_total
    }

    /// Drops since the last call (for periodic logging).
    pub fn take_dropped_unreported(&self) -> u64 {
        std::mem::take(&mut self.lock().dropped_unreported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(id: &str) -> CheckResult {
        CheckResult {
            check_id: id.into(),
            started_at: "2026-10-03T05:00:00.000Z".into(),
            duration_ms: 1,
            ok: true,
            status_code: None,
            error: None,
            timings: None,
            tls_expires_at: None,
            remote_ip: None,
            response_bytes: None,
        }
    }

    fn ids(b: &Batch) -> Vec<&str> {
        b.results.iter().map(|r| r.check_id.as_str()).collect()
    }

    #[test]
    fn drops_oldest_when_full() {
        let buf = ResultBuffer::new(3);
        for i in 0..5 {
            buf.push(r(&i.to_string()));
        }
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.dropped_total(), 2);
        assert_eq!(buf.take_dropped_unreported(), 2);
        assert_eq!(buf.take_dropped_unreported(), 0);
        assert_eq!(ids(&buf.peek(10).unwrap()), ["2", "3", "4"]);
    }

    #[test]
    fn peek_then_ack() {
        let buf = ResultBuffer::new(10);
        for i in 0..5 {
            buf.push(r(&i.to_string()));
        }
        let b = buf.peek(2).unwrap();
        assert_eq!(ids(&b), ["0", "1"]);
        assert_eq!(buf.len(), 5, "peek does not remove");
        buf.ack(&b);
        assert_eq!(ids(&buf.peek(10).unwrap()), ["2", "3", "4"]);
    }

    #[test]
    fn ack_after_overflow_keeps_newer_results() {
        let buf = ResultBuffer::new(3);
        for i in 0..3 {
            buf.push(r(&i.to_string()));
        }
        let b = buf.peek(2).unwrap(); // "0", "1" in flight
        for i in 3..5 {
            buf.push(r(&i.to_string())); // drops "0" and "1"
        }
        buf.ack(&b);
        assert_eq!(ids(&buf.peek(10).unwrap()), ["2", "3", "4"]);
    }

    #[test]
    fn empty() {
        let buf = ResultBuffer::default();
        assert!(buf.peek(10).is_none());
        assert!(buf.is_empty());
    }
}
