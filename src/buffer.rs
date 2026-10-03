//! Bounded in-memory buffer of unsent results, limited by count and by
//! bytes. Over the byte budget, body samples are dropped from the oldest
//! results first; if that isn't enough, or the buffer is full, the oldest
//! results are dropped and counted.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::details::{json_len, strip_body_sample};
use crate::protocol::CheckResult;

/// Protocol limit on buffered results.
pub const DEFAULT_CAPACITY: usize = 10_000;
/// Default byte budget for buffered results (serialised size). Keeps the
/// agent well under the 128 MiB systemd memory cap.
pub const DEFAULT_MAX_BYTES: usize = 64 << 20;
/// Default largest batch, in serialised bytes (at least one result is
/// always sent).
pub const DEFAULT_BATCH_BYTES: usize = 8 << 20;

pub struct ResultBuffer {
    inner: Mutex<Inner>,
}

struct Entry {
    seq: u64,
    bytes: usize,
    result: Arc<CheckResult>,
}

struct Inner {
    queue: VecDeque<Entry>,
    capacity: usize,
    max_bytes: usize,
    bytes: usize,
    next_seq: u64,
    /// Every entry with a lower seq has had its body sample removed.
    stripped_below: u64,
    dropped_total: u64,
    dropped_unreported: u64,
    stripped_total: u64,
}

/// A batch peeked from the buffer. Results stay buffered until [`ResultBuffer::ack`].
pub struct Batch {
    pub results: Vec<Arc<CheckResult>>,
    last_seq: u64,
}

impl Default for ResultBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl ResultBuffer {
    pub fn new(capacity: usize) -> Self {
        Self::with_limits(capacity, DEFAULT_MAX_BYTES)
    }

    pub fn with_limits(capacity: usize, max_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                queue: VecDeque::new(),
                capacity: capacity.max(1),
                max_bytes: max_bytes.max(1),
                bytes: 0,
                next_seq: 0,
                stripped_below: 0,
                dropped_total: 0,
                dropped_unreported: 0,
                stripped_total: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding this lock can't leave the queue inconsistent.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn push(&self, result: CheckResult) {
        let bytes = json_len(&result);
        let mut g = self.lock();
        while g.queue.len() >= g.capacity {
            g.drop_oldest();
        }
        let seq = g.next_seq;
        g.next_seq += 1;
        g.bytes += bytes;
        g.queue.push_back(Entry {
            seq,
            bytes,
            result: Arc::new(result),
        });
        if g.bytes > g.max_bytes {
            g.strip_samples();
        }
        // Never drop the result just added: it alone is within the
        // per-result budget, far below the buffer budget.
        while g.bytes > g.max_bytes && g.queue.len() > 1 {
            g.drop_oldest();
        }
    }

    /// Copies up to `max` of the oldest results without removing them, so a
    /// request that fails or is cancelled loses nothing.
    pub fn peek(&self, max: usize) -> Option<Batch> {
        self.peek_bytes(max, usize::MAX)
    }

    /// Like [`peek`](Self::peek), also stopping before the batch exceeds
    /// `max_bytes` (it always holds at least one result).
    pub fn peek_bytes(&self, max: usize, max_bytes: usize) -> Option<Batch> {
        let g = self.lock();
        if g.queue.is_empty() || max == 0 {
            return None;
        }
        let mut results = Vec::with_capacity(max.min(g.queue.len()));
        let mut last_seq = 0;
        let mut bytes = 0usize;
        for e in g.queue.iter().take(max) {
            if !results.is_empty() && bytes.saturating_add(e.bytes) > max_bytes {
                break;
            }
            bytes += e.bytes;
            results.push(e.result.clone());
            last_seq = e.seq;
        }
        Some(Batch { results, last_seq })
    }

    /// Removes the results of a delivered batch. Safe even if some of them
    /// were already dropped for space in the meantime.
    pub fn ack(&self, batch: &Batch) {
        let mut g = self.lock();
        while g.queue.front().is_some_and(|e| e.seq <= batch.last_seq) {
            if let Some(e) = g.queue.pop_front() {
                g.bytes -= e.bytes;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.lock().queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Serialised size of the buffered results.
    pub fn bytes(&self) -> usize {
        self.lock().bytes
    }

    pub fn dropped_total(&self) -> u64 {
        self.lock().dropped_total
    }

    /// Results whose body sample was removed to stay within the byte budget.
    pub fn stripped_total(&self) -> u64 {
        self.lock().stripped_total
    }

    /// Drops since the last call (for periodic logging).
    pub fn take_dropped_unreported(&self) -> u64 {
        std::mem::take(&mut self.lock().dropped_unreported)
    }
}

impl Inner {
    fn drop_oldest(&mut self) {
        if let Some(e) = self.queue.pop_front() {
            self.bytes -= e.bytes;
            self.dropped_total += 1;
            self.dropped_unreported += 1;
        }
    }

    /// Removes body samples, oldest first, until the buffer fits its budget.
    fn strip_samples(&mut self) {
        let from = self.queue.partition_point(|e| e.seq < self.stripped_below);
        for i in from..self.queue.len() {
            if self.bytes <= self.max_bytes {
                return;
            }
            let e = &mut self.queue[i];
            // Clones the result only if a batch in flight still holds it.
            if strip_body_sample(Arc::make_mut(&mut e.result)) {
                let bytes = json_len(e.result.as_ref());
                let old = std::mem::replace(&mut e.bytes, bytes);
                self.bytes = self.bytes - old + bytes;
                self.stripped_total += 1;
            }
            self.stripped_below = self.queue[i].seq + 1;
        }
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
            details: None,
            confirm_nonce: None,
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

    fn with_sample(id: &str, n: usize) -> CheckResult {
        let mut r = r(id);
        let mut b = crate::details::BodyCapture::new(true);
        b.push(&vec![b'a'; n]);
        r.details = Some(crate::details::Details {
            http_version: None,
            ip_family: None,
            request: None,
            status_text: None,
            response_headers: vec![],
            body: Some(b.finish(Some("text/plain".into()))),
            redirects: vec![],
            tls: None,
            timings: None,
        });
        r
    }

    fn has_sample(r: &CheckResult) -> bool {
        r.details
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
            .sample
            .is_some()
    }

    #[test]
    fn byte_budget_strips_samples_oldest_first() {
        let one = json_len(&with_sample("0", 10_000));
        // Room for ~3.5 results with samples.
        let buf = ResultBuffer::with_limits(100, one * 7 / 2);
        for i in 0..4 {
            buf.push(with_sample(&i.to_string(), 10_000));
        }
        assert_eq!(buf.len(), 4, "nothing dropped");
        assert_eq!(buf.dropped_total(), 0);
        assert_eq!(buf.stripped_total(), 1);
        assert!(buf.bytes() <= one * 7 / 2);
        let b = buf.peek(10).unwrap();
        let samples: Vec<bool> = b.results.iter().map(|r| has_sample(r)).collect();
        assert_eq!(samples, [false, true, true, true]);
    }

    #[test]
    fn byte_budget_drops_oldest_when_stripping_is_not_enough() {
        let one = json_len(&with_sample("0", 10_000));
        let buf = ResultBuffer::with_limits(100, one + one / 5);
        for i in 0..50 {
            buf.push(with_sample(&i.to_string(), 10_000));
        }
        assert!(buf.bytes() <= one + one / 5);
        assert!(buf.dropped_total() > 0);
        let b = buf.peek(100).unwrap();
        assert_eq!(b.results.last().unwrap().check_id, "49", "newest kept");
        // Results outrank samples: every sample goes before any result does.
        assert!(b.results.iter().all(|r| !has_sample(r)));
    }

    #[test]
    fn stripping_does_not_touch_batches_in_flight() {
        let one = json_len(&with_sample("0", 10_000));
        let buf = ResultBuffer::with_limits(100, one * 3);
        buf.push(with_sample("0", 10_000));
        let in_flight = buf.peek(1).unwrap();
        for i in 1..4 {
            buf.push(with_sample(&i.to_string(), 10_000));
        }
        assert!(has_sample(&in_flight.results[0]));
    }

    #[test]
    fn batches_respect_a_byte_limit() {
        let buf = ResultBuffer::new(100);
        for i in 0..10 {
            buf.push(r(&i.to_string()));
        }
        let one = json_len(&r("0"));
        assert_eq!(buf.peek_bytes(100, one * 3).unwrap().results.len(), 3);
        assert_eq!(
            buf.peek_bytes(100, 1).unwrap().results.len(),
            1,
            "at least one"
        );
        let b = buf.peek_bytes(100, usize::MAX).unwrap();
        assert_eq!(b.results.len(), 10);
        buf.ack(&b);
        assert_eq!(buf.bytes(), 0);
    }

    #[test]
    fn empty() {
        let buf = ResultBuffer::default();
        assert!(buf.peek(10).is_none());
        assert!(buf.is_empty());
    }
}
