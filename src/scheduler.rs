//! Per-check timers on the wall clock.
//!
//! - With a `schedule` from the platform (round robin, protocol 1.2.0), a check runs at the UTC
//!   times `t` where `(t − epoch − phase) mod every == 0`, plus a fixed jitter of at most 2 s from
//!   its id (the same on every agent, so the places of one monitor stay exactly one interval apart).
//! - Without one (an older platform), every `interval_seconds` at a stable offset derived from its
//!   id, so checks are spread across the interval and keep their phase across restarts.
//!
//! A check's timer task lives as long as the check is assigned: a changed definition or schedule is
//! handed to the running task, which re-plans without restarting, never runs the same slot twice and
//! never runs two scheduled checks less than half an interval apart. Confirmation requests run once,
//! straight away, at most one per check per 10 s, each nonce once. A semaphore caps concurrent checks.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::buffer::ResultBuffer;
use crate::probe::Prober;
use crate::protocol::{Check, CheckResult, ConfirmRequest};

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

/// The wall clock in Unix milliseconds (UTC). Tests drive a virtual one.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The system clock (NTP-synced on bynh's servers; round robin relies on it).
pub fn system_clock() -> Clock {
    Arc::new(unix_ms)
}

/// At most one confirmation run per check per this long.
pub const CONFIRM_MIN_GAP: Duration = Duration::from_secs(10);
/// How long a confirmation nonce is remembered (the platform lists a request for 2 minutes).
pub const NONCE_MEMORY: Duration = Duration::from_secs(15 * 60);
/// Largest jitter added to a scheduled run.
pub const MAX_JITTER_MS: u64 = 2_000;
/// A timer re-reads the wall clock at least this often, so a clock step is caught.
const MAX_SLEEP: Duration = Duration::from_secs(60);
/// A wake-up this close before its slot (by the wall clock) runs it.
const EARLY_TOLERANCE_MS: u64 = 20;

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

/// The fixed delay added to a scheduled check's runs: `hash(id) mod min(2 s, every / 2)`.
pub fn jitter_ms(id: &str, every_ms: u64) -> u64 {
    fnv1a(id) % MAX_JITTER_MS.min(every_ms / 2).max(1)
}

/// First run time (Unix ms) at or after `now_ms` that sits on the grid
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

/// When a check runs, on the wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    /// Time between runs.
    pub every_ms: u64,
    /// Runs fall on `phase + k × every` (Unix ms).
    pub phase_ms: u64,
    /// Two scheduled runs are never closer than this (half the check's interval).
    pub guard_ms: u64,
}

impl Plan {
    pub fn of(check: &Check) -> Self {
        let interval = interval_ms(check.interval_seconds);
        match check.schedule.map(|s| s.normalized(check.interval_seconds)) {
            Some(s) => {
                let every_s = i128::from(s.every_seconds);
                let base_s =
                    (i128::from(s.epoch) + i128::from(s.phase_seconds)).rem_euclid(every_s);
                let every = s.every_seconds * 1000;
                // base_s < every_s ≤ a week, so this fits.
                let base = u64::try_from(base_s).unwrap_or(0) * 1000;
                Self {
                    every_ms: every,
                    phase_ms: (base + jitter_ms(&check.id, every)) % every,
                    guard_ms: interval.min(every) / 2,
                }
            }
            None => Self {
                every_ms: interval,
                phase_ms: stable_offset_ms(&check.id, interval),
                guard_ms: interval / 2,
            },
        }
    }

    /// The next run at or after `now_ms`, never the slot that ran last (`last_ms`) again and
    /// never within `guard_ms` after it.
    pub fn next_ms(&self, now_ms: u64, last_ms: Option<u64>) -> u64 {
        let from = match last_ms {
            Some(last) => now_ms.max(last.saturating_add(self.guard_ms.max(1))),
            None => now_ms,
        };
        next_run_ms(from, self.every_ms, self.phase_ms)
    }
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
    /// Definition or schedule changed: handed to the running timer.
    pub changed: usize,
    pub removed: usize,
    pub unchanged: usize,
}

/// What [`Scheduler::confirm`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmStats {
    pub run: usize,
    /// Nonce already seen.
    pub duplicate: usize,
    /// Check not assigned to this agent.
    pub unknown: usize,
    /// Another confirmation of the check ran less than 10 s ago.
    pub limited: usize,
}

struct Entry {
    check: Arc<Check>,
    update: watch::Sender<Arc<Check>>,
    confirm: mpsc::UnboundedSender<String>,
    handle: JoinHandle<()>,
}

pub struct Scheduler<R: CheckRunner> {
    runner: Arc<R>,
    buffer: Arc<ResultBuffer>,
    permits: Arc<Semaphore>,
    clock: Clock,
    entries: HashMap<String, Entry>,
    /// Confirmation nonces seen, and when.
    nonces: HashMap<String, Instant>,
    /// Last confirmation run per check.
    last_confirm: HashMap<String, Instant>,
}

impl<R: CheckRunner> Scheduler<R> {
    pub fn new(runner: Arc<R>, buffer: Arc<ResultBuffer>, concurrency: usize) -> Self {
        Self::with_clock(runner, buffer, concurrency, system_clock())
    }

    pub fn with_clock(
        runner: Arc<R>,
        buffer: Arc<ResultBuffer>,
        concurrency: usize,
        clock: Clock,
    ) -> Self {
        Self {
            runner,
            buffer,
            permits: Arc::new(Semaphore::new(concurrency.max(1))),
            clock,
            entries: HashMap::new(),
            nonces: HashMap::new(),
            last_confirm: HashMap::new(),
        }
    }

    /// Replaces the assignment set. Timers of checks that stay keep running: a changed
    /// definition or schedule is handed to them; removed checks stop.
    pub fn apply(&mut self, checks: Vec<Check>) -> ApplyStats {
        let mut stats = ApplyStats::default();
        let mut next: HashMap<String, Entry> = HashMap::with_capacity(checks.len());
        for check in checks {
            if next.contains_key(&check.id) {
                tracing::warn!(check_id = %check.id, "duplicate check id in assignments; keeping the first");
                continue;
            }
            match self.entries.remove(&check.id) {
                Some(mut old) if !old.handle.is_finished() => {
                    if *old.check == check {
                        stats.unchanged += 1;
                    } else {
                        stats.changed += 1;
                        old.check = Arc::new(check);
                        old.update.send_replace(old.check.clone());
                    }
                    next.insert(old.check.id.clone(), old);
                }
                Some(_) => {
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
            self.last_confirm.remove(&id);
            stats.removed += 1;
        }
        self.entries = next;
        stats
    }

    /// Runs each confirmation request once, straight away: a nonce seen before is skipped, so is
    /// a check that isn't assigned, and a check confirmed less than 10 s ago.
    pub fn confirm(&mut self, requests: &[ConfirmRequest]) -> ConfirmStats {
        let mut stats = ConfirmStats::default();
        let now = Instant::now();
        self.nonces
            .retain(|_, seen| now.duration_since(*seen) < NONCE_MEMORY);
        for r in requests {
            if self.nonces.contains_key(&r.nonce) {
                stats.duplicate += 1;
                continue;
            }
            self.nonces.insert(r.nonce.clone(), now);
            let Some(entry) = self.entries.get(&r.check_id) else {
                stats.unknown += 1;
                continue;
            };
            if self
                .last_confirm
                .get(&r.check_id)
                .is_some_and(|t| now.duration_since(*t) < CONFIRM_MIN_GAP)
            {
                stats.limited += 1;
                continue;
            }
            if entry.confirm.send(r.nonce.clone()).is_ok() {
                self.last_confirm.insert(r.check_id.clone(), now);
                stats.run += 1;
            }
        }
        stats
    }

    /// Stops every timer (on 401, 426 and shutdown).
    pub fn stop_all(&mut self) {
        for (id, e) in self.entries.drain() {
            e.handle.abort();
            self.runner.forget(&id);
        }
        self.last_confirm.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn spawn(&self, check: Check) -> Entry {
        let check = Arc::new(check);
        let (update, updates) = watch::channel(check.clone());
        let (confirm, confirms) = mpsc::unbounded_channel();
        let handle = tokio::spawn(run_timer(
            updates,
            confirms,
            Ctx {
                runner: self.runner.clone(),
                buffer: self.buffer.clone(),
                permits: self.permits.clone(),
                clock: self.clock.clone(),
            },
        ));
        Entry {
            check,
            update,
            confirm,
            handle,
        }
    }
}

impl<R: CheckRunner> Drop for Scheduler<R> {
    fn drop(&mut self) {
        self.stop_all();
    }
}

struct Ctx<R: CheckRunner> {
    runner: Arc<R>,
    buffer: Arc<ResultBuffer>,
    permits: Arc<Semaphore>,
    clock: Clock,
}

async fn run_timer<R: CheckRunner>(
    mut updates: watch::Receiver<Arc<Check>>,
    mut confirms: mpsc::UnboundedReceiver<String>,
    ctx: Ctx<R>,
) {
    // The slot that ran last, on the wall clock: survives definition and schedule changes.
    let mut last_slot: Option<u64> = None;
    loop {
        let check = updates.borrow_and_update().clone();
        let plan = Plan::of(&check);
        let now = (ctx.clock)();
        let slot = plan.next_ms(now, last_slot);
        let wait = Duration::from_millis(slot.saturating_sub(now)).min(MAX_SLEEP);
        tokio::select! {
            biased;
            changed = updates.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            Some(nonce) = confirms.recv() => {
                if !run_once(&check, Some(nonce), &ctx).await {
                    return;
                }
            }
            _ = tokio::time::sleep(wait) => {
                // Woken early to re-read the clock (long waits): plan again.
                if (ctx.clock)().saturating_add(EARLY_TOLERANCE_MS) >= slot {
                    if !run_once(&check, None, &ctx).await {
                        return;
                    }
                    last_slot = Some(slot);
                }
            }
        }
    }
}

/// Runs the check once and buffers the result; false when the semaphore is closed.
async fn run_once<R: CheckRunner>(check: &Check, nonce: Option<String>, ctx: &Ctx<R>) -> bool {
    let Ok(permit) = ctx.permits.acquire().await else {
        return false;
    };
    let mut result = ctx.runner.run(check).await;
    drop(permit);
    result.confirm_nonce = nonce;
    tracing::debug!(
        check_id = %result.check_id,
        ok = result.ok,
        status = ?result.status_code,
        duration_ms = result.duration_ms,
        error = ?result.error,
        confirm = result.confirm_nonce.is_some(),
        "check finished"
    );
    ctx.buffer.push(result);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{CheckType, Schedule};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// 2026-10-14 08:00:00 UTC: a multiple of every turn length used below.
    const T0: u64 = 1_791_964_800_000;

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

    fn scheduled(id: &str, interval: u64, every: u64, phase: u64, epoch: i64) -> Check {
        let mut c = check(id, interval);
        c.schedule = Some(Schedule {
            every_seconds: every,
            phase_seconds: phase,
            epoch,
        });
        c
    }

    #[test]
    fn a_schedule_runs_on_the_wall_clock_grid() {
        let c = scheduled("mon_1", 60, 300, 137, 0);
        let p = Plan::of(&c);
        let j = jitter_ms("mon_1", 300_000);
        assert!(j < MAX_JITTER_MS);
        assert_eq!(
            p,
            Plan {
                every_ms: 300_000,
                phase_ms: 137_000 + j,
                guard_ms: 30_000
            }
        );
        // On the boundary: now. A millisecond later: the next turn. UTC milliseconds, no DST.
        let first = T0 + 137_000 + j;
        assert_eq!(p.next_ms(first, None), first);
        assert_eq!(p.next_ms(first + 1, None), first + 300_000);
        assert_eq!(p.next_ms(T0, None), first);
        assert_eq!(p.next_ms(T0 - 1, None), first);
        for now in [T0 + 1, T0 + 299_999, T0 + 86_400_000 * 180 + 4_321] {
            let t = p.next_ms(now, None);
            assert!(t >= now && t < now + 300_000);
            assert_eq!((t - j) % 300_000, 137_000);
        }

        // The epoch shifts the grid, also backwards.
        let p = Plan::of(&scheduled("mon_1", 60, 300, 137, -5));
        assert_eq!(p.phase_ms, 132_000 + j);
        let p = Plan::of(&scheduled("mon_1", 60, 300, 0, 1_000_000_007));
        assert_eq!(p.phase_ms, 107_000 + j); // 1,000,000,007 mod 300 = 107

        // Nonsense from the platform is clamped: at least the interval, at most a week, phase wraps.
        let p = Plan::of(&scheduled("mon_1", 60, 0, 5, 0));
        assert_eq!(p.every_ms, 60_000);
        assert!(p.phase_ms < 60_000);
        let p = Plan::of(&scheduled("mon_1", 60, u64::MAX, u64::MAX, i64::MIN));
        assert_eq!(
            p.every_ms,
            crate::protocol::limits::MAX_EVERY_SECONDS * 1000
        );
        assert!(p.phase_ms < p.every_ms);
        assert!(p.next_ms(u64::MAX - 1, None) >= u64::MAX - 1);
    }

    #[test]
    fn without_a_schedule_it_runs_every_interval_as_before() {
        let c = check("mon_1", 60);
        assert_eq!(
            Plan::of(&c),
            Plan {
                every_ms: 60_000,
                phase_ms: stable_offset_ms("mon_1", 60_000),
                guard_ms: 30_000
            }
        );
    }

    #[test]
    fn jitter_is_at_most_two_seconds_and_half_a_turn() {
        for i in 0..1000 {
            let id = format!("mon_{i}");
            assert!(jitter_ms(&id, 300_000) < 2_000);
            assert!(jitter_ms(&id, 1_000) < 500);
            assert_eq!(
                jitter_ms(&id, 300_000),
                jitter_ms(&id, 60_000),
                "same on every place"
            );
        }
    }

    #[test]
    fn the_last_slot_never_runs_twice() {
        let p = Plan::of(&scheduled("mon_1", 60, 300, 0, 0));
        let slot = p.next_ms(T0, None);
        assert_eq!(p.next_ms(slot, Some(slot)), slot + 300_000);
        assert_eq!(
            p.next_ms(slot - 5, Some(slot)),
            slot + 300_000,
            "clock stepped back"
        );
        // A new phase one interval on is fine; one closer than half an interval is not.
        let moved = Plan::of(&scheduled("mon_1", 60, 300, 60, 0));
        assert_eq!(moved.next_ms(slot + 10, Some(slot)), slot + 60_000);
        let close = Plan::of(&scheduled("mon_1", 60, 300, 20, 0));
        assert_eq!(close.next_ms(slot + 10, Some(slot)), slot + 320_000);
    }

    #[tokio::test(start_paused = true)]
    async fn huge_interval_check_does_not_spin() {
        let (runner, _clock) = fake(T0);
        let buf = Arc::new(ResultBuffer::default());
        let mut s = sched(&runner, buf, 2);
        let mut c = check("big", 1);
        c.interval_seconds = 1 << 61; // 2^61 × 1000 used to wrap to 0
        s.apply(vec![c]);
        tokio::time::sleep(Duration::from_secs(2 * 86_400)).await;
        assert!(runner.calls.load(Ordering::SeqCst) <= 3);
    }

    struct Fake {
        calls: AtomicUsize,
        active: AtomicUsize,
        max_active: AtomicUsize,
        forgotten: Mutex<Vec<String>>,
        /// (check id, wall-clock start in ms)
        runs: Mutex<Vec<(String, u64)>>,
        clock: Clock,
        work: Duration,
    }

    impl CheckRunner for Fake {
        fn run(&self, check: &Check) -> impl Future<Output = CheckResult> + Send {
            let id = check.id.clone();
            async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.runs.lock().unwrap().push((id.clone(), (self.clock)()));
                let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_active.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(self.work).await;
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
                    confirm_nonce: None,
                }
            }
        }
        fn forget(&self, check_id: &str) {
            self.forgotten.lock().unwrap().push(check_id.to_owned());
        }
    }

    /// A wall clock that starts at `start_ms` and moves with tokio's (paused) time, plus a step
    /// that tests can add to (an NTP correction).
    struct VirtualClock {
        base: Instant,
        start_ms: u64,
        step_ms: AtomicU64,
    }

    impl VirtualClock {
        fn now(&self) -> u64 {
            self.start_ms
                + u64::try_from(Instant::now().duration_since(self.base).as_millis()).unwrap()
                + self.step_ms.load(Ordering::SeqCst)
        }
    }

    fn fake(start_ms: u64) -> (Arc<Fake>, Arc<VirtualClock>) {
        let vc = Arc::new(VirtualClock {
            base: Instant::now(),
            start_ms,
            step_ms: AtomicU64::new(0),
        });
        let c = vc.clone();
        let clock: Clock = Arc::new(move || c.now());
        (
            Arc::new(Fake {
                calls: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                max_active: AtomicUsize::new(0),
                forgotten: Mutex::new(Vec::new()),
                runs: Mutex::new(Vec::new()),
                clock,
                work: Duration::from_millis(500),
            }),
            vc,
        )
    }

    fn sched(runner: &Arc<Fake>, buf: Arc<ResultBuffer>, n: usize) -> Scheduler<Fake> {
        Scheduler::with_clock(runner.clone(), buf, n, runner.clock.clone())
    }

    fn check(id: &str, interval: u64) -> Check {
        let mut c = Check::new(id, CheckType::Tcp);
        c.interval_seconds = interval;
        c
    }

    fn runs(f: &Fake) -> Vec<u64> {
        f.runs.lock().unwrap().iter().map(|(_, t)| *t).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_unchanged_timers() {
        let buf = Arc::new(ResultBuffer::default());
        let (runner, _clock) = fake(T0);
        let mut s = sched(&runner, buf, 4);
        let st = s.apply(vec![check("a", 60), check("b", 60), check("c", 60)]);
        assert_eq!(
            st,
            ApplyStats {
                added: 3,
                ..Default::default()
            }
        );
        let handle_a = s.entries["a"].handle.id();
        let handle_b = s.entries["b"].handle.id();

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
        assert_eq!(
            s.entries["b"].handle.id(),
            handle_b,
            "changed timer updated in place"
        );
        assert_eq!(s.entries["b"].check.interval_seconds, 30);
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
        let (runner, _clock) = fake(T0);
        let buf = Arc::new(ResultBuffer::default());
        let mut s = sched(&runner, buf.clone(), 2);
        s.apply((0..10).map(|i| check(&format!("c{i}"), 1)).collect());
        tokio::time::sleep(Duration::from_millis(10_500)).await;
        let calls = runner.calls.load(Ordering::SeqCst);
        assert!(calls >= 30, "only {calls} runs");
        assert!(runner.max_active.load(Ordering::SeqCst) <= 2);
        assert!(buf.len() >= 30);
    }

    #[tokio::test(start_paused = true)]
    async fn a_scheduled_check_runs_once_per_turn_at_its_slot() {
        let (runner, _clock) = fake(T0 - 10_000);
        let mut s = sched(&runner, Arc::new(ResultBuffer::default()), 4);
        s.apply(vec![scheduled("mon_1", 60, 300, 120, 0)]);
        tokio::time::sleep(Duration::from_secs(18 * 60)).await;
        let j = jitter_ms("mon_1", 300_000);
        let first = T0 + 120_000 + j;
        assert_eq!(
            runs(&runner),
            [first, first + 300_000, first + 600_000, first + 900_000]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_phase_takes_over_without_gaps_or_repeats() {
        let (runner, _clock) = fake(T0 - 10_000);
        let mut s = sched(&runner, Arc::new(ResultBuffer::default()), 4);
        let j = jitter_ms("mon_1", 300_000);
        s.apply(vec![scheduled("mon_1", 60, 300, 0, 0)]);
        let handle = s.entries["mon_1"].handle.id();
        tokio::time::sleep(Duration::from_secs(15)).await;
        assert_eq!(runs(&runner), [T0 + j]);

        // A place left the rotation: our turn moved a minute on. It runs there, once.
        assert_eq!(s.apply(vec![scheduled("mon_1", 60, 240, 60, 0)]).changed, 1);
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(runs(&runner), [T0 + j, T0 + 60_000 + j]);

        // Back to the first schedule right after: its next slot, not the one already run.
        s.apply(vec![scheduled("mon_1", 60, 300, 0, 0)]);
        tokio::time::sleep(Duration::from_secs(300)).await;
        assert_eq!(runs(&runner), [T0 + j, T0 + 60_000 + j, T0 + 300_000 + j]);
        assert_eq!(s.entries["mon_1"].handle.id(), handle, "never restarted");

        // A definition change on the slot just run doesn't run it again.
        let mut c = scheduled("mon_1", 60, 300, 0, 0);
        c.timeout_ms = 5_000;
        s.apply(vec![c]);
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(runner.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn more_places_mean_longer_turns_on_the_same_grid() {
        let (runner, _clock) = fake(T0 - 10_000);
        let mut s = sched(&runner, Arc::new(ResultBuffer::default()), 4);
        let j = jitter_ms("mon_1", 180_000);
        // Three places, slot 1.
        s.apply(vec![scheduled("mon_1", 60, 180, 60, 0)]);
        tokio::time::sleep(Duration::from_secs(75)).await;
        assert_eq!(runs(&runner), [T0 + 60_000 + j]);
        // Five places now, slot 3: next turn at T0 + 180 s.
        s.apply(vec![scheduled("mon_1", 60, 300, 180, 0)]);
        tokio::time::sleep(Duration::from_secs(420)).await;
        assert_eq!(
            runs(&runner),
            [T0 + 60_000 + j, T0 + 180_000 + j, T0 + 480_000 + j]
        );
        for w in runs(&runner).windows(2) {
            assert_eq!(
                (w[1] - w[0]) % 60_000,
                0,
                "always a whole number of intervals apart"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_clock_step_is_caught_within_a_minute() {
        let (runner, clock) = fake(T0);
        let mut s = sched(&runner, Arc::new(ResultBuffer::default()), 4);
        let j = jitter_ms("mon_1", 3_600_000);
        s.apply(vec![scheduled("mon_1", 60, 3600, 0, 0)]);
        tokio::time::sleep(Duration::from_secs(3)).await; // ran at T0 + j
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
        // NTP steps the clock 59 minutes forward, past most of the wait for the next turn
        // (T0 + 1 h): the timer, re-reading the clock at least every minute, runs it then.
        clock.step_ms.store(59 * 60_000, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(125)).await;
        let r = runs(&runner);
        assert_eq!(r.len(), 2, "{r:?}");
        assert!(
            (T0 + 3_600_000 + j..T0 + 3_660_000 + j).contains(&r[1]),
            "{r:?}"
        );
    }

    fn ask(id: &str, nonce: &str) -> ConfirmRequest {
        ConfirmRequest {
            check_id: id.into(),
            requested_at: None,
            nonce: nonce.into(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn confirmations_run_at_once_once_per_nonce_and_at_most_every_ten_seconds() {
        let (runner, _clock) = fake(T0 - 10_000);
        let buf = Arc::new(ResultBuffer::default());
        let mut s = sched(&runner, buf.clone(), 4);
        s.apply(vec![scheduled("mon_1", 60, 300, 0, 0)]);
        // Let the scheduled run at T0 happen, then ask straight after it.
        tokio::time::sleep(Duration::from_secs(12)).await;
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);

        let st = s.confirm(&[ask("mon_1", "n1"), ask("mon_1", "n2"), ask("mon_x", "n3")]);
        assert_eq!(
            st,
            ConfirmStats {
                run: 1,
                limited: 1,
                unknown: 1,
                duplicate: 0
            }
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            runner.calls.load(Ordering::SeqCst),
            2,
            "even right after a scheduled run"
        );

        // The platform lists the request until it hears back: the same nonce never runs again.
        assert_eq!(s.confirm(&[ask("mon_1", "n1")]).duplicate, 1);
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(s.confirm(&[ask("mon_1", "n1")]).duplicate, 1);
        assert_eq!(s.confirm(&[ask("mon_1", "n4")]).run, 1);
        tokio::time::sleep(Duration::from_secs(1)).await;

        let nonces: Vec<Option<String>> = buf
            .peek(10)
            .unwrap()
            .results
            .iter()
            .map(|r| r.confirm_nonce.clone())
            .collect();
        assert_eq!(nonces, [None, Some("n1".into()), Some("n4".into())]);
        // Scheduled turns carry on as planned.
        tokio::time::sleep(Duration::from_secs(300)).await;
        assert_eq!(runner.calls.load(Ordering::SeqCst), 4);
    }
}
