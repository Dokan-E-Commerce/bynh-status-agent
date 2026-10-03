//! The agent's control loop: hello → poll assignments / report results, with
//! the protocol's handling of 401, 426, 429 and 5xx, and a final flush on
//! shutdown.

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use tokio::time::{sleep, sleep_until, Instant};
use tokio_util::sync::CancellationToken;

use crate::backoff::Backoff;
use crate::buffer::ResultBuffer;
use crate::config::{redact_token, Config};
use crate::net::Net;
use crate::netguard::Guard;
use crate::platform::{ApiError, AssignmentsOutcome, PlatformClient};
use crate::probe::Prober;
use crate::protocol::{rfc3339, version_cmp, HelloRequest, HelloResponse, AGENT_VERSION};
use crate::scheduler::Scheduler;

/// Timing knobs. Defaults follow the protocol; tests shorten them.
#[derive(Debug, Clone)]
pub struct Tunables {
    /// Wait after a 401 before trying hello again.
    pub auth_retry: Duration,
    /// Wait after a 426 before trying again.
    pub upgrade_retry: Duration,
    pub backoff_base: Duration,
    pub backoff_cap: Duration,
    /// How long shutdown may spend flushing buffered results.
    pub flush_deadline: Duration,
    /// Timeout for each platform request.
    pub request_timeout: Duration,
    /// Batches sent per report tick, so a large backlog can't starve polling.
    pub max_batches_per_tick: usize,
    /// Buffer capacity (the protocol's 10,000).
    pub buffer_capacity: usize,
}

impl Default for Tunables {
    fn default() -> Self {
        Self {
            auth_retry: Duration::from_secs(300),
            upgrade_retry: Duration::from_secs(3600),
            backoff_base: Duration::from_secs(1),
            backoff_cap: Duration::from_secs(300),
            flush_deadline: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            max_batches_per_tick: 20,
            buffer_capacity: crate::buffer::DEFAULT_CAPACITY,
        }
    }
}

/// Settings received in the hello response, clamped to sane ranges.
#[derive(Debug, Clone, Copy)]
struct Session {
    poll: Duration,
    report: Duration,
    max_batch: usize,
}

impl Session {
    fn from_hello(h: &HelloResponse) -> Self {
        Self {
            poll: Duration::from_secs(h.poll_interval_seconds.clamp(1, 3600)),
            report: Duration::from_secs(h.report_interval_seconds.clamp(1, 3600)),
            max_batch: h.max_batch.clamp(1, 10_000),
        }
    }
}

enum SessionEnd {
    Shutdown,
    Unauthorized,
    Upgrade {
        message: Option<String>,
        minimum_version: Option<String>,
    },
}

pub struct Agent {
    config: Config,
    tun: Tunables,
    client: PlatformClient,
    buffer: Arc<ResultBuffer>,
    scheduler: Scheduler<Prober>,
    started_at: OffsetDateTime,
    etag: Option<String>,
    max_batch: usize,
    /// True after a successful hello, false after 401/426.
    authorized: bool,
}

impl Agent {
    pub fn new(config: Config, tun: Tunables) -> Result<Self, String> {
        let token = config
            .require_token()
            .map_err(|e| e.to_string())?
            .to_owned();
        let net = Arc::new(Net::new(config.ca_file.as_deref())?);
        let prober = Arc::new(Prober::new(
            net.clone(),
            Guard::new(config.allow_private),
            config.report_ip,
        ));
        let buffer = Arc::new(ResultBuffer::new(tun.buffer_capacity));
        let scheduler = Scheduler::new(prober, buffer.clone(), config.concurrency);
        let client = PlatformClient::new(net, &config.api_url, &token, tun.request_timeout);
        Ok(Self {
            config,
            tun,
            client,
            buffer,
            scheduler,
            started_at: OffsetDateTime::now_utc(),
            etag: None,
            max_batch: 500,
            authorized: false,
        })
    }

    /// The result buffer (exposed for tests and diagnostics).
    pub fn buffer(&self) -> Arc<ResultBuffer> {
        self.buffer.clone()
    }

    /// Runs until `shutdown` is cancelled, then flushes buffered results
    /// within the flush deadline.
    pub async fn run(mut self, shutdown: CancellationToken) {
        tracing::info!(
            version = AGENT_VERSION,
            api_url = %self.config.api_url,
            token = %self.config.token.as_deref().map(redact_token).unwrap_or_default(),
            allow_private = self.config.allow_private,
            report_ip = self.config.report_ip,
            concurrency = self.config.concurrency,
            config_file = ?self.config.source,
            "bynh-status-agent starting"
        );

        let mut backoff = Backoff::new(self.tun.backoff_base, self.tun.backoff_cap);
        let mut wait: Option<Duration> = None;
        loop {
            if let Some(d) = wait.take() {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = sleep(d) => {}
                }
            }
            let request = self.hello_request();
            let hello = tokio::select! {
                _ = shutdown.cancelled() => break,
                r = self.client.hello(&request) => r,
            };
            let end = match hello {
                Ok(h) => {
                    backoff.reset();
                    self.session(h, &shutdown).await
                }
                Err(ApiError::Unauthorized) => SessionEnd::Unauthorized,
                Err(ApiError::UpgradeRequired {
                    message,
                    minimum_version,
                }) => SessionEnd::Upgrade {
                    message,
                    minimum_version,
                },
                Err(e) => {
                    let d = backoff.next_delay(retry_after(&e));
                    tracing::warn!(error = %e, retry_in = ?d, "hello failed; retrying");
                    wait = Some(d);
                    continue;
                }
            };
            match end {
                SessionEnd::Shutdown => break,
                SessionEnd::Unauthorized => {
                    self.suspend();
                    tracing::error!(
                        retry_in = ?self.tun.auth_retry,
                        "the platform rejected the agent token (401): it was revoked or is wrong. \
                         Checks are stopped. Create a new token in bynh under Settings → Agents and \
                         restart the agent with it. Retrying hello every 5 minutes."
                    );
                    wait = Some(self.tun.auth_retry);
                }
                SessionEnd::Upgrade {
                    message,
                    minimum_version,
                } => {
                    self.suspend();
                    tracing::error!(
                        version = AGENT_VERSION,
                        minimum_version = minimum_version.as_deref().unwrap_or("unknown"),
                        message = message.as_deref().unwrap_or(""),
                        retry_in = ?self.tun.upgrade_retry,
                        "this bynh-status-agent version is too old for the platform (426). Checks are \
                         stopped. Upgrade the agent; retrying hourly."
                    );
                    wait = Some(self.tun.upgrade_retry);
                }
            }
        }

        self.scheduler.stop_all();
        self.final_flush().await;
        tracing::info!("bynh-status-agent stopped");
    }

    fn hello_request(&self) -> HelloRequest {
        HelloRequest {
            version: AGENT_VERSION.to_owned(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            hostname: self
                .config
                .send_hostname
                .then(|| gethostname::gethostname().to_string_lossy().into_owned())
                .filter(|h| !h.is_empty()),
            started_at: rfc3339(self.started_at),
        }
    }

    /// Stops all checks after a 401 or 426 and forgets the assignment version,
    /// so the full set is fetched again after recovery.
    fn suspend(&mut self) {
        self.scheduler.stop_all();
        self.etag = None;
        self.authorized = false;
    }

    async fn session(&mut self, hello: HelloResponse, shutdown: &CancellationToken) -> SessionEnd {
        let s = Session::from_hello(&hello);
        self.max_batch = s.max_batch;
        self.authorized = true;
        tracing::info!(
            agent_id = %hello.agent.id,
            name = hello.agent.name.as_deref().unwrap_or(""),
            kind = hello.agent.kind.as_deref().unwrap_or(""),
            region = hello.agent.region.as_deref().unwrap_or(""),
            poll_interval = ?s.poll,
            report_interval = ?s.report,
            max_batch = s.max_batch,
            "connected to bynh"
        );
        if let Some(latest) = hello.latest_version.as_deref() {
            if version_cmp(latest, AGENT_VERSION) == Some(std::cmp::Ordering::Greater) {
                tracing::info!(
                    latest_version = latest,
                    "a newer bynh-status-agent is available"
                );
            }
        }
        if let Some(min) = hello.minimum_version.as_deref() {
            if version_cmp(min, AGENT_VERSION) == Some(std::cmp::Ordering::Greater) {
                tracing::warn!(
                    minimum_version = min,
                    "this bynh-status-agent is older than the platform's minimum version; upgrade soon"
                );
            }
        }

        let mut poll_backoff = Backoff::new(self.tun.backoff_base, self.tun.backoff_cap);
        let mut report_backoff = Backoff::new(self.tun.backoff_base, self.tun.backoff_cap);
        let mut next_poll = Instant::now();
        let mut next_report = Instant::now() + s.report;

        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return SessionEnd::Shutdown,
                _ = sleep_until(next_poll) => {
                    let r = tokio::select! {
                        _ = shutdown.cancelled() => return SessionEnd::Shutdown,
                        r = self.poll() => r,
                    };
                    match r {
                        Ok(()) => {
                            poll_backoff.reset();
                            next_poll = Instant::now() + s.poll;
                        }
                        Err(e) => match fatal(e) {
                            Ok(end) => return end,
                            Err(e) => {
                                let d = poll_backoff.next_delay(retry_after(&e));
                                tracing::warn!(error = %e, retry_in = ?d, "polling assignments failed");
                                next_poll = Instant::now() + d;
                            }
                        },
                    }
                }
                _ = sleep_until(next_report) => {
                    let r = tokio::select! {
                        _ = shutdown.cancelled() => return SessionEnd::Shutdown,
                        r = self.flush(self.tun.max_batches_per_tick) => r,
                    };
                    match r {
                        Ok(()) => {
                            report_backoff.reset();
                            next_report = Instant::now() + s.report;
                        }
                        Err(e) => match fatal(e) {
                            Ok(end) => return end,
                            Err(e) => {
                                let d = report_backoff.next_delay(retry_after(&e));
                                tracing::warn!(
                                    error = %e,
                                    retry_in = ?d,
                                    buffered = self.buffer.len(),
                                    "reporting results failed; keeping them buffered"
                                );
                                next_report = Instant::now() + d;
                            }
                        },
                    }
                }
            }
        }
    }

    async fn poll(&mut self) -> Result<(), ApiError> {
        match self.client.assignments(self.etag.as_deref()).await? {
            AssignmentsOutcome::NotModified => {
                tracing::debug!("assignments unchanged");
            }
            AssignmentsOutcome::Changed { assignments, etag } => {
                for (id, reason) in &assignments.skipped {
                    tracing::warn!(check_id = id.as_deref().unwrap_or("?"), %reason, "skipping a check this agent does not understand");
                }
                let version = assignments.config_version.clone();
                let stats = self.scheduler.apply(assignments.checks);
                tracing::info!(
                    config_version = %version,
                    checks = self.scheduler.len(),
                    added = stats.added,
                    changed = stats.changed,
                    removed = stats.removed,
                    unchanged = stats.unchanged,
                    "assignments updated"
                );
                self.etag = Some(etag);
            }
        }
        Ok(())
    }

    /// Sends up to `max_batches` batches. Results leave the buffer only once
    /// the platform has accepted the batch.
    async fn flush(&mut self, max_batches: usize) -> Result<(), ApiError> {
        let dropped = self.buffer.take_dropped_unreported();
        if dropped > 0 {
            tracing::warn!(
                dropped,
                dropped_total = self.buffer.dropped_total(),
                "result buffer full; oldest results were dropped"
            );
        }
        for _ in 0..max_batches {
            let Some(batch) = self.buffer.peek(self.max_batch) else {
                break;
            };
            match self.client.results(&batch.results).await {
                Ok(resp) => {
                    self.buffer.ack(&batch);
                    if !resp.rejected.is_empty() {
                        let unknown = resp
                            .rejected
                            .iter()
                            .filter(|r| r.reason == "unknown_check")
                            .count();
                        tracing::debug!(
                            rejected = resp.rejected.len(),
                            unknown_check = unknown,
                            "platform rejected some results"
                        );
                        let invalid = resp.rejected.len() - unknown;
                        if invalid > 0 {
                            tracing::warn!(invalid, "platform rejected results as invalid");
                        }
                    }
                    tracing::debug!(
                        sent = batch.results.len(),
                        accepted = resp.accepted,
                        "results reported"
                    );
                }
                Err(ApiError::Rejected { status, message }) => {
                    // Retrying a batch the platform calls malformed would block
                    // every later result behind it.
                    self.buffer.ack(&batch);
                    tracing::error!(status, %message, dropped = batch.results.len(), "platform refused a results batch; dropping it");
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    async fn final_flush(&mut self) {
        if !self.authorized || self.buffer.is_empty() {
            return;
        }
        let pending = self.buffer.len();
        match tokio::time::timeout(self.tun.flush_deadline, self.flush(usize::MAX)).await {
            Ok(Ok(())) => tracing::info!(sent = pending, "flushed buffered results"),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, unsent = self.buffer.len(), "could not flush buffered results")
            }
            Err(_) => tracing::warn!(
                unsent = self.buffer.len(),
                "flush deadline reached; unsent results discarded"
            ),
        }
    }
}

/// Splits 401/426 (which end the session) from retryable errors.
fn fatal(e: ApiError) -> Result<SessionEnd, ApiError> {
    match e {
        ApiError::Unauthorized => Ok(SessionEnd::Unauthorized),
        ApiError::UpgradeRequired {
            message,
            minimum_version,
        } => Ok(SessionEnd::Upgrade {
            message,
            minimum_version,
        }),
        other => Err(other),
    }
}

fn retry_after(e: &ApiError) -> Option<Duration> {
    match e {
        ApiError::Retryable { retry_after, .. } => *retry_after,
        _ => None,
    }
}
