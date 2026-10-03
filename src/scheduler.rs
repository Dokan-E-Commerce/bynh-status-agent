//! Per-check timers. Each check runs every `interval_seconds`, at a stable
//! offset derived from its id, so checks are spread across the interval and
//! keep their phase across restarts. A semaphore caps concurrent checks.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::buffer::ResultBuffer;
use crate::probe::Prober;
use crate::protocol::{Check, CheckResult};

/// Anything that can run a check (the real [`Prober`], or a fake in tests).
pub trait CheckRunner: Send + Sync + 'static {
    fn run(&self, check: &Check) -> impl Future<Output = CheckResult> + Send;
    /// Called when a check is unassigned, to drop per-check state.
    fn forget(&self, _check_id: &str) {}
}

impl CheckRunner for Prober {
    fn run(&self, check: &Check) -> impl Future<Output = CheckResult> + Send {
        Prober::run(self, check)
    }
    fn forget(&self, check_id: &str) {
        Prober::forget(self, check_id)
    }
}

/// 64-bit FNV-1a: tiny, and stable across platforms, builds and restarts
/// (unlike `std`'s `DefaultHasher`).
pub fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A check's interval in ms, clamped to 1 s – 24 h whatever the platform
/// sent (so the timer arithmetic can't overflow or spin).
pub fn interval_ms(interval_seconds: u64) -> u64 {
    interval_seconds
        .clamp(1, crate::protocol::limits::MAX_INTERVAL_SECONDS)
        .saturating_mul(1000)
}

/// Offset of a check within its interval, in ms: `hash(id) mod interval`.
pub fn stable_offset_ms(id: &str, interval_ms: u64) -> u64 {
    fnv1a(id) % interval_ms.max(1)
}

/// First run time (Unix ms) at or after `now_ms` that sits on the check's grid
/// `offset + k × interval`.
pub fn next_run_ms(now_ms: u64, interval_ms: u64, offset_ms: u64) -> u64 {
    let interval_ms = interval_ms.max(1);
    let offset_ms = offset_ms % interval_ms;
    if now_ms <= offset_ms {
        return offset_ms;
    }
    let k = (now_ms - offset_ms).div_ceil(interval_ms);
    offset_ms.saturating_add(k.saturating_mul(interval_ms))
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// What [`Scheduler::apply`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ApplyStats {
    pub added: usize,
    pub changed: usize,
    pub removed: usize,
    pub unchanged: usize,
}

struct Entry {
    check: Arc<Check>,
    handle: JoinHandle<()>,
}

pub struct Scheduler<R: CheckRunner> {
    runner: Arc<R>,
    buffer: Arc<ResultBuffer>,
    permits: Arc<Semaphore>,
    entries: HashMap<String, Entry>,
}

impl<R: CheckRunner> Scheduler<R> {
    pub fn new(runner: Arc<R>, buffer: Arc<ResultBuffer>, concurrency: usize) -> Self {
        Self {
            runner,
            buffer,
            permits: Arc::new(Semaphore::new(concurrency.max(1))),
            entries: HashMap::new(),
        }
    }

    /// Replaces the assignment set. Timers of checks whose definition did not
    /// change keep running untouched; changed checks restart, removed ones stop.
    pub fn apply(&mut self, checks: Vec<Check>) -> ApplyStats {
        let mut stats = ApplyStats::default();
        let mut next: HashMap<String, Entry> = HashMap::with_capacity(checks.len());
        for check in checks {
            if next.contains_key(&check.id) {
                tracing::warn!(check_id = %check.id, "duplicate check id in assignments; keeping the first");
                continue;
            }
            match self.entries.remove(&check.id) {
                Some(old) if *old.check == check && !old.handle.is_finished() => {
                    stats.unchanged += 1;
                    next.insert(check.id.clone(), old);
                }
                Some(old) => {
                    old.handle.abort();
                    stats.changed += 1;
                    let e = self.spawn(check);
                    next.insert(e.check.id.clone(), e);
                }
                None => {
                    stats.added += 1;
                    let e = self.spawn(check);
                    next.insert(e.check.id.clone(), e);
                }
            }
        }
        for (id, old) in self.entries.drain() {
            old.handle.abort();
            self.runner.forget(&id);
            stats.removed += 1;
        }
        self.entries = next;
        stats
    }

    /// Stops every timer (on 401, 426 and shutdown).
    pub fn stop_all(&mut self) {
        for (id, e) in self.entries.drain() {
            e.handle.abort();
            self.runner.forget(&id);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn spawn(&self, check: Check) -> Entry {
        let check = Arc::new(check);
        let handle = tokio::spawn(run_timer(
            check.clone(),
            self.runner.clone(),
            self.buffer.clone(),
            self.permits.clone(),
        ));
        Entry { check, handle }
    }
}

impl<R: CheckRunner> Drop for Scheduler<R> {
    fn drop(&mut self) {
        self.stop_all();
    }
}

async fn run_timer<R: CheckRunner>(
    check: Arc<Check>,
    runner: Arc<R>,
    buffer: Arc<ResultBuffer>,
    permits: Arc<Semaphore>,
) {
    let interval_ms = interval_ms(check.interval_seconds);
    assert!(interval_ms > 0, "check interval must be positive");
    let interval = Duration::from_millis(interval_ms);
    let offset = stable_offset_ms(&check.id, interval_ms);
    let now = unix_ms();
    let mut next =
        Instant::now() + Duration::from_millis(next_run_ms(now, interval_ms, offset) - now);
    loop {
        tokio::time::sleep_until(next).await;
        let Ok(permit) = permits.acquire().await else {
            return;
        };
        let result = runner.run(&check).await;
        drop(permit);
        tracing::debug!(
            check_id = %result.check_id,
            ok = result.ok,
            status = ?result.status_code,
            duration_ms = result.duration_ms,
            error = ?result.error,
            "check finished"
        );
        buffer.push(result);
        // Skip runs we missed (slow check or a saturated semaphore) instead of
        // firing them back to back.
        next += interval;
        let now = Instant::now();
        while next <= now {
            next += interval;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::CheckType;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn offsets_are_stable_and_bounded() {
        assert_eq!(fnv1a(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a("a"), 0xaf63_dc4c_8601_ec8c);
        let a = stable_offset_ms("mon_123", 60_000);
        assert_eq!(a, stable_offset_ms("mon_123", 60_000));
        assert!(a < 60_000);
        // ids spread over the interval
        let mut buckets = [0usize; 10];
        for i in 0..1000 {
            let o = stable_offset_ms(&format!("mon_{i}"), 60_000);
            buckets[(o / 6_000) as usize] += 1;
        }
        assert!(buckets.iter().all(|&n| n > 50), "{buckets:?}");
    }

    #[test]
    fn huge_intervals_are_clamped() {
        let day = 86_400_000;
        assert_eq!(interval_ms(u64::MAX), day);
        assert_eq!(interval_ms(1 << 61), day);
        assert_eq!(interval_ms(0), 1000);
        let now = 1_759_467_600_123;
        let t = next_run_ms(
            now,
            interval_ms(1 << 61),
            stable_offset_ms("m", interval_ms(1 << 61)),
        );
        assert!(t >= now && t < now + day);
    }

    #[tokio::test(start_paused = true)]
    async fn huge_interval_check_does_not_spin() {
        let runner = fake();
        let buf = Arc::new(ResultBuffer::default());
        let mut s = Scheduler::new(runner.clone(), buf, 2);
        let mut c = check("big", 1);
        c.interval_seconds = 1 << 61; // 2^61 × 1000 used to wrap to 0
        s.apply(vec![c]);
        tokio::time::sleep(Duration::from_secs(2 * 86_400)).await;
        assert!(runner.calls.load(Ordering::SeqCst) <= 3);
    }

    #[test]
    fn next_run_on_grid() {
        assert_eq!(next_run_ms(0, 60_000, 5_000), 5_000);
        assert_eq!(next_run_ms(5_000, 60_000, 5_000), 5_000);
        assert_eq!(next_run_ms(5_001, 60_000, 5_000), 65_000);
        assert_eq!(next_run_ms(1_000_000, 60_000, 5_000), 1_025_000);
        let t = next_run_ms(1_759_467_600_123, 30_000, 777);
        assert!((1_759_467_600_123..1_759_467_600_123 + 30_000).contains(&t));
        assert_eq!(t % 30_000, 777);
    }

    struct Fake {
        calls: AtomicUsize,
        active: AtomicUsize,
        max_active: AtomicUsize,
        forgotten: std::sync::Mutex<Vec<String>>,
    }

    impl CheckRunner for Fake {
        fn run(&self, check: &Check) -> impl Future<Output = CheckResult> + Send {
            let id = check.id.clone();
            async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_active.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(500)).await;
                self.active.fetch_sub(1, Ordering::SeqCst);
                CheckResult {
                    check_id: id,
                    started_at: String::new(),
                    duration_ms: 500,
                    ok: true,
                    status_code: None,
                    error: None,
                    timings: None,
                    tls_expires_at: None,
                    remote_ip: None,
                    response_bytes: None,
                    details: None,
                }
            }
        }
        fn forget(&self, check_id: &str) {
            self.forgotten.lock().unwrap().push(check_id.to_owned());
        }
    }

    fn fake() -> Arc<Fake> {
        Arc::new(Fake {
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            forgotten: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn check(id: &str, interval: u64) -> Check {
        let mut c = Check::new(id, CheckType::Tcp);
        c.interval_seconds = interval;
        c
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_unchanged_timers() {
        let buf = Arc::new(ResultBuffer::default());
        let runner = fake();
        let mut s = Scheduler::new(runner.clone(), buf, 4);
        let st = s.apply(vec![check("a", 60), check("b", 60), check("c", 60)]);
        assert_eq!(
            st,
            ApplyStats {
                added: 3,
                ..Default::default()
            }
        );
        let handle_a = s.entries["a"].handle.id();

        let st = s.apply(vec![check("a", 60), check("b", 30), check("d", 60)]);
        assert_eq!(
            st,
            ApplyStats {
                added: 1,
                changed: 1,
                removed: 1,
                unchanged: 1
            }
        );
        assert_eq!(s.entries["a"].handle.id(), handle_a, "unchanged timer kept");
        assert_eq!(s.len(), 3);
        assert_eq!(
            *runner.forgotten.lock().unwrap(),
            ["c"],
            "removed check forgotten"
        );
        s.stop_all();
        assert!(s.is_empty());
        let mut all = runner.forgotten.lock().unwrap().clone();
        all.sort();
        assert_eq!(all, ["a", "b", "c", "d"]);
    }

    #[tokio::test(start_paused = true)]
    async fn runs_every_interval_within_concurrency() {
        let runner = fake();
        let buf = Arc::new(ResultBuffer::default());
        let mut s = Scheduler::new(runner.clone(), buf.clone(), 2);
        s.apply((0..10).map(|i| check(&format!("c{i}"), 1)).collect());
        tokio::time::sleep(Duration::from_millis(10_500)).await;
        let calls = runner.calls.load(Ordering::SeqCst);
        assert!(calls >= 30, "only {calls} runs");
        assert!(runner.max_active.load(Ordering::SeqCst) <= 2);
        assert!(buf.len() >= 30);
    }
}
