//! Wire types for the bynh agent protocol, v1 (see `PROTOCOL.md`).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

/// Value of the `X-Bynh-Agent-Protocol` header.
pub const PROTOCOL_VERSION: &str = "1";

/// Header carrying [`PROTOCOL_VERSION`] on every platform request.
pub const PROTOCOL_HEADER: &str = "X-Bynh-Agent-Protocol";
/// Platform endpoints (relative to `api_url`).
pub const PATH_HELLO: &str = "/api/v1/agent/hello";
pub const PATH_ASSIGNMENTS: &str = "/api/v1/agent/assignments";
pub const PATH_RESULTS: &str = "/api/v1/agent/results";
/// Methods a check may use.
pub const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// Bounds applied to assignments, so a broken or hostile platform response
/// can't exhaust the agent.
pub mod limits {
    pub const MAX_CHECKS: usize = 10_000;
    pub const MAX_ID: usize = 128;
    pub const MAX_URL: usize = 8 * 1024;
    pub const MAX_HOST: usize = 253;
    pub const MAX_HEADERS: usize = 50;
    pub const MAX_HEADER_VALUE: usize = 8 * 1024;
    pub const MAX_BODY: usize = 64 * 1024;
    pub const MAX_KEYWORD: usize = 1024;
    pub const MAX_INTERVAL_SECONDS: u64 = 86_400;
    pub const MAX_TIMEOUT_MS: u64 = 120_000;
    pub const MAX_REDIRECTS: u32 = 20;
}

/// Version of this agent build.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `User-Agent` sent on every request: `bynh-status-agent/<version> (<os>; <arch>)`.
pub fn user_agent() -> String {
    format!(
        "bynh-status-agent/{} ({}; {})",
        AGENT_VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

/// Treats an explicit JSON `null` like a missing field.
fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

// ---------------------------------------------------------------------------
// hello

#[derive(Debug, Serialize)]
pub struct HelloRequest {
    pub version: String,
    pub os: String,
    pub arch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub started_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HelloResponse {
    pub agent: AgentInfo,
    #[serde(default = "default_poll")]
    pub poll_interval_seconds: u64,
    #[serde(default = "default_report")]
    pub report_interval_seconds: u64,
    #[serde(default = "default_max_batch")]
    pub max_batch: usize,
    #[serde(default)]
    pub minimum_version: Option<String>,
    #[serde(default)]
    pub latest_version: Option<String>,
}

fn default_poll() -> u64 {
    30
}
fn default_report() -> u64 {
    10
}
fn default_max_batch() -> usize {
    500
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
}

/// Body of a `426 Upgrade Required` response.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpgradeRequired {
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub minimum_version: Option<String>,
}

// ---------------------------------------------------------------------------
// assignments

/// Raw assignments document. Checks are kept as JSON values so one malformed
/// or unknown check never takes down the whole set (see [`Assignments::parse`]).
#[derive(Debug, Deserialize)]
struct RawAssignments {
    config_version: String,
    #[serde(default, deserialize_with = "null_default")]
    checks: Vec<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct Assignments {
    pub config_version: String,
    pub checks: Vec<Check>,
    /// Checks that could not be understood: (id if printable, reason). The
    /// reason is a fixed category and never contains values from the check.
    pub skipped: Vec<(Option<String>, &'static str)>,
    /// Checks beyond [`limits::MAX_CHECKS`] that were ignored.
    pub truncated: usize,
}

impl Assignments {
    pub fn parse(body: &[u8]) -> Result<Self, serde_json::Error> {
        let raw: RawAssignments = serde_json::from_slice(body)?;
        let total = raw.checks.len();
        let mut checks = Vec::with_capacity(total.min(limits::MAX_CHECKS));
        let mut skipped = Vec::new();
        for value in raw.checks.into_iter().take(limits::MAX_CHECKS) {
            let id = value
                .get("id")
                .and_then(|v| v.as_str())
                .filter(|s| printable_id(s))
                .map(str::to_owned);
            let known = matches!(
                value.get("type").and_then(|v| v.as_str()),
                Some("http" | "keyword" | "tcp" | "tls")
            );
            if !known {
                skipped.push((id, "unsupported check type"));
                continue;
            }
            match serde_json::from_value::<Check>(value) {
                Ok(c) => match c.validate() {
                    Ok(c) => checks.push(c),
                    Err(reason) => skipped.push((id, reason)),
                },
                Err(_) => skipped.push((id, "invalid field types")),
            }
        }
        Ok(Self {
            config_version: raw.config_version,
            checks,
            skipped,
            truncated: total.saturating_sub(limits::MAX_CHECKS),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckType {
    Http,
    Keyword,
    Tcp,
    Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
pub enum IpVersion {
    #[default]
    #[serde(rename = "any")]
    Any,
    #[serde(rename = "4")]
    V4,
    #[serde(rename = "6")]
    V6,
}

/// Credentials for the monitored target. Never logged.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Auth {
    Basic { username: String, password: String },
    Bearer { token: String },
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Auth::Basic { .. } => f.write_str("Basic(<redacted>)"),
            Auth::Bearer { .. } => f.write_str("Bearer(<redacted>)"),
        }
    }
}

/// One assigned check. `PartialEq` is used to decide whether a timer can be kept
/// when the assignment set changes.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct Check {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: CheckType,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default = "default_method", deserialize_with = "method_or_default")]
    pub method: String,
    #[serde(default, deserialize_with = "null_default")]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub auth: Option<Auth>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
    #[serde(default, deserialize_with = "null_default")]
    pub expected_statuses: Vec<String>,
    #[serde(default)]
    pub keyword: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub keyword_absent: bool,
    #[serde(default = "default_true", deserialize_with = "bool_or_true")]
    pub follow_redirects: bool,
    #[serde(default = "default_max_redirects")]
    pub max_redirects: u32,
    #[serde(default = "default_true", deserialize_with = "bool_or_true")]
    pub verify_tls: bool,
    #[serde(default, deserialize_with = "null_default")]
    pub ip_version: IpVersion,
    /// Send a body sample with the result's details (default true).
    #[serde(default = "default_true", deserialize_with = "bool_or_true")]
    pub capture_body: bool,
}

fn default_method() -> String {
    "GET".to_owned()
}
fn default_timeout_ms() -> u64 {
    10_000
}
fn default_interval() -> u64 {
    60
}
fn default_true() -> bool {
    true
}
fn default_max_redirects() -> u32 {
    5
}
fn method_or_default<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_else(default_method))
}
fn bool_or_true<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    Ok(Option::<bool>::deserialize(d)?.unwrap_or(true))
}

impl fmt::Debug for Check {
    // Hand-written so header values and auth never end up in logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Check")
            .field("id", &self.id)
            .field("type", &self.kind)
            .field("url", &self.url.as_deref().map(crate::redact::url_for_log))
            .field("host", &self.host)
            .field("port", &self.port)
            .field("method", &self.method)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("has_body", &self.body.is_some())
            .field("auth", &self.auth)
            .field("timeout_ms", &self.timeout_ms)
            .field("interval_seconds", &self.interval_seconds)
            .field("expected_statuses", &self.expected_statuses)
            .field("keyword_set", &self.keyword.is_some())
            .field("keyword_absent", &self.keyword_absent)
            .field("follow_redirects", &self.follow_redirects)
            .field("max_redirects", &self.max_redirects)
            .field("verify_tls", &self.verify_tls)
            .field("ip_version", &self.ip_version)
            .field("capture_body", &self.capture_body)
            .finish()
    }
}

/// Ids that are safe to print in logs.
fn printable_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= limits::MAX_ID
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

impl Check {
    /// Checks limits and normalises a check from the platform. Errors are
    /// fixed descriptions that never echo the offending value.
    pub fn validate(mut self) -> Result<Self, &'static str> {
        use limits::*;
        if self.id.is_empty() || self.id.len() > MAX_ID {
            return Err("id missing or too long");
        }
        let method = self.method.trim().to_ascii_uppercase();
        if !METHODS.contains(&method.as_str()) {
            return Err("method not allowed");
        }
        self.method = method;
        self.interval_seconds = self.interval_seconds.clamp(1, MAX_INTERVAL_SECONDS);
        self.timeout_ms = self.timeout_ms.clamp(1, MAX_TIMEOUT_MS);
        self.max_redirects = self.max_redirects.min(MAX_REDIRECTS);
        if let Some(u) = &self.url {
            if u.len() > MAX_URL {
                return Err("url too long");
            }
            let parsed = url::Url::parse(u).map_err(|_| "invalid url")?;
            if parsed.host().is_none() {
                return Err("url has no host");
            }
            if matches!(self.kind, CheckType::Http | CheckType::Keyword)
                && !matches!(parsed.scheme(), "http" | "https")
            {
                return Err("url scheme must be http or https");
            }
        } else if matches!(self.kind, CheckType::Http | CheckType::Keyword) {
            return Err("url missing");
        }
        if let Some(h) = &self.host {
            if h.is_empty() {
                self.host = None;
            } else {
                self.host = Some(crate::net::normalize_host(h).map_err(|_| "invalid host")?);
            }
        }
        if matches!(self.kind, CheckType::Tcp | CheckType::Tls)
            && self.host.is_none()
            && self.url.is_none()
        {
            return Err("host missing");
        }
        if self.headers.len() > MAX_HEADERS {
            return Err("too many headers");
        }
        for (k, v) in &self.headers {
            if v.len() > MAX_HEADER_VALUE
                || http::HeaderName::from_bytes(k.trim().as_bytes()).is_err()
                || http::HeaderValue::from_str(v).is_err()
            {
                return Err("invalid header");
            }
        }
        if self.body.as_ref().is_some_and(|b| b.len() > MAX_BODY) {
            return Err("body too large");
        }
        if self.keyword.as_ref().is_some_and(|k| k.len() > MAX_KEYWORD) {
            return Err("keyword too long");
        }
        Ok(self)
    }

    /// A bare check with protocol defaults, used by `bynh-status-agent check` and tests.
    pub fn new(id: impl Into<String>, kind: CheckType) -> Self {
        Self {
            id: id.into(),
            kind,
            url: None,
            host: None,
            port: None,
            method: default_method(),
            headers: BTreeMap::new(),
            body: None,
            auth: None,
            timeout_ms: default_timeout_ms(),
            interval_seconds: default_interval(),
            expected_statuses: Vec::new(),
            keyword: None,
            keyword_absent: false,
            follow_redirects: true,
            max_redirects: default_max_redirects(),
            verify_tls: true,
            ip_version: IpVersion::Any,
            capture_body: true,
        }
    }
}

// ---------------------------------------------------------------------------
// results

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ErrorKind {
    Dns,
    Connect,
    Timeout,
    Tls,
    Status,
    Keyword,
    Redirects,
    Blocked,
    Other,
}

/// Maximum length of `error.message`, in characters.
pub const MAX_ERROR_MESSAGE: usize = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckError {
    pub kind: ErrorKind,
    pub message: String,
}

impl CheckError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        let mut message: String = message.into();
        if message.chars().count() > MAX_ERROR_MESSAGE {
            message = message.chars().take(MAX_ERROR_MESSAGE - 1).collect();
            message.push('…');
        }
        Self { kind, message }
    }
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for CheckError {}

/// Per-phase timings in milliseconds. A phase that did not happen (no DNS for an
/// IP literal is reported as 0; no TLS on plain HTTP or TCP, no TTFB on TCP/TLS
/// checks) is `null`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Timings {
    pub dns_ms: Option<u64>,
    pub connect_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    pub check_id: String,
    pub started_at: String,
    pub duration_ms: u64,
    pub ok: bool,
    pub status_code: Option<u16>,
    pub error: Option<CheckError>,
    pub timings: Option<Timings>,
    pub tls_expires_at: Option<String>,
    pub remote_ip: Option<String>,
    pub response_bytes: Option<u64>,
    /// Check details (agent 1.1.0). Absent only on results built outside the
    /// prober.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<crate::details::Details>,
}

#[derive(Debug, Serialize)]
pub struct ResultsRequest<'a> {
    pub results: &'a [&'a CheckResult],
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ResultsResponse {
    #[serde(default)]
    pub accepted: usize,
    #[serde(default, deserialize_with = "null_default")]
    pub rejected: Vec<Rejected>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rejected {
    pub index: usize,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// time helpers

/// RFC 3339 with millisecond precision in UTC, e.g. `2026-10-03T05:00:00.123Z`.
pub fn rfc3339(t: time::OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    let fmt = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    t.format(&fmt)
        .unwrap_or_else(|_| t.unix_timestamp().to_string())
}

/// Compares dotted versions numerically (`1.10.0 > 1.9.3`); pre-release suffixes
/// are ignored. Returns `None` if either side does not parse.
pub fn version_cmp(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    fn parse(v: &str) -> Option<Vec<u64>> {
        let core = v.trim().trim_start_matches('v');
        let core = core.split(['-', '+']).next()?;
        core.split('.').map(|p| p.parse().ok()).collect()
    }
    let (mut a, mut b) = (parse(a)?, parse(b)?);
    let n = a.len().max(b.len());
    a.resize(n, 0);
    b.resize(n, 0);
    Some(a.cmp(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn parses_protocol_example() {
        let body = br#"{ "config_version": "c_8f2",
          "checks": [{
            "id": "mon_123", "type": "http", "url": "https://shop.example.com/health",
            "host": null, "port": null, "method": "GET", "headers": { "X-Probe": "1" },
            "body": null, "auth": { "type": "basic", "username": "u", "password": "p" },
            "timeout_ms": 10000, "interval_seconds": 60,
            "expected_statuses": ["2xx", "3xx", "401"], "keyword": null, "keyword_absent": false,
            "follow_redirects": true, "max_redirects": 5, "verify_tls": true, "ip_version": "4"
          }, {
            "id": "mon_db", "type": "tcp", "host": "db.internal", "port": 5432
          }, {
            "id": "mon_future", "type": "dns", "host": "example.com"
          }]}"#;
        let a = Assignments::parse(body).unwrap();
        assert_eq!(a.config_version, "c_8f2");
        assert_eq!(a.checks.len(), 2);
        assert_eq!(a.skipped.len(), 1);
        assert_eq!(
            a.skipped[0],
            (Some("mon_future".to_owned()), "unsupported check type")
        );
        let c = &a.checks[0];
        assert_eq!(c.ip_version, IpVersion::V4);
        assert!(matches!(c.auth, Some(Auth::Basic { .. })));
        let tcp = &a.checks[1];
        assert_eq!(tcp.kind, CheckType::Tcp);
        assert_eq!(tcp.port, Some(5432));
        assert_eq!(tcp.method, "GET");
        assert!(tcp.follow_redirects && tcp.verify_tls);
        assert!(
            c.capture_body && tcp.capture_body,
            "capture_body defaults to true"
        );
    }

    #[test]
    fn capture_body_can_be_turned_off() {
        let a = parse_one(serde_json::json!({ "capture_body": false }));
        assert!(!a.checks[0].capture_body);
        let a = parse_one(serde_json::json!({ "capture_body": null }));
        assert!(a.checks[0].capture_body);
    }

    fn check_json(extra: serde_json::Value) -> serde_json::Value {
        let mut v =
            serde_json::json!({ "id": "mon_1", "type": "http", "url": "https://example.com/" });
        for (k, val) in extra.as_object().unwrap() {
            v[k] = val.clone();
        }
        v
    }

    fn parse_one(extra: serde_json::Value) -> Assignments {
        let doc = serde_json::json!({ "config_version": "c", "checks": [check_json(extra)] });
        Assignments::parse(&serde_json::to_vec(&doc).unwrap()).unwrap()
    }

    #[test]
    fn limits_and_normalisation() {
        use serde_json::json;
        let ok = parse_one(
            json!({ "method": "post", "interval_seconds": u64::MAX, "timeout_ms": 0, "max_redirects": 1000 }),
        );
        let c = &ok.checks[0];
        assert_eq!(c.method, "POST");
        assert_eq!(c.interval_seconds, limits::MAX_INTERVAL_SECONDS);
        assert_eq!(c.timeout_ms, 1);
        assert_eq!(c.max_redirects, limits::MAX_REDIRECTS);
        let i = parse_one(json!({ "interval_seconds": 0 }));
        assert_eq!(i.checks[0].interval_seconds, 1);

        let many: serde_json::Map<String, serde_json::Value> =
            (0..51).map(|i| (format!("x-h{i}"), json!("v"))).collect();
        for (extra, reason) in [
            (json!({ "method": "TRACE" }), "method not allowed"),
            (json!({ "method": "GET\r\nX: y" }), "method not allowed"),
            (json!({ "id": "x".repeat(129) }), "id missing or too long"),
            (
                json!({ "url": format!("https://example.com/{}", "a".repeat(9000)) }),
                "url too long",
            ),
            (
                json!({ "url": "ftp://example.com/" }),
                "url scheme must be http or https",
            ),
            (json!({ "headers": many }), "too many headers"),
            (
                json!({ "headers": { "x-a": "v".repeat(8193) } }),
                "invalid header",
            ),
            (
                json!({ "headers": { "x-a": "bad\r\nInjected: 1" } }),
                "invalid header",
            ),
            (json!({ "headers": { "bad name": "v" } }), "invalid header"),
            (json!({ "body": "b".repeat(65_537) }), "body too large"),
            (json!({ "keyword": "k".repeat(1025) }), "keyword too long"),
            (json!({ "timeout_ms": "soon" }), "invalid field types"),
        ] {
            let a = parse_one(extra);
            assert!(a.checks.is_empty());
            assert_eq!(a.skipped[0].1, reason);
        }
    }

    #[test]
    fn rejects_host_injection() {
        use serde_json::json;
        for host in [
            "evil.com:443 HTTP/1.1\r\nHost: x\r\n\r\nGET /admin",
            "a b",
            "host/../x",
            "user@host",
            "[::1]x",
        ] {
            let a = parse_one(json!({ "type": "tcp", "url": null, "host": host, "port": 1 }));
            assert!(a.checks.is_empty(), "{host:?} accepted");
            assert_eq!(a.skipped[0].1, "invalid host");
        }
        let a =
            parse_one(json!({ "type": "tcp", "url": null, "host": "[2001:db8::1]", "port": 1 }));
        assert_eq!(a.checks[0].host.as_deref(), Some("2001:db8::1"));
        let a = parse_one(
            json!({ "type": "tls", "url": null, "host": "Shop.Example.COM", "port": 443 }),
        );
        assert_eq!(a.checks[0].host.as_deref(), Some("shop.example.com"));
    }

    #[test]
    fn caps_the_number_of_checks() {
        let checks: Vec<_> = (0..limits::MAX_CHECKS + 5)
            .map(|i| serde_json::json!({ "id": format!("m{i}"), "type": "tcp", "host": "example.com", "port": 1 }))
            .collect();
        let doc = serde_json::json!({ "config_version": "c", "checks": checks });
        let a = Assignments::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(a.checks.len(), limits::MAX_CHECKS);
        assert_eq!(a.truncated, 5);
    }

    #[test]
    fn skipped_reasons_never_echo_values() {
        let a = parse_one(
            serde_json::json!({ "timeout_ms": "secret-value", "id": "bad id with spaces" }),
        );
        assert_eq!(a.skipped[0], (None, "invalid field types"));
    }

    #[test]
    fn debug_never_shows_secrets() {
        let mut c = Check::new("mon_1", CheckType::Http);
        c.url = Some("https://user:hunter2@example.com/?token=abc".into());
        c.headers.insert("X-Api-Key".into(), "sekrit-value".into());
        c.auth = Some(Auth::Bearer {
            token: "tok-123".into(),
        });
        let s = format!("{c:?}");
        assert!(!s.contains("hunter2"), "{s}");
        assert!(!s.contains("sekrit-value"), "{s}");
        assert!(!s.contains("tok-123"), "{s}");
        assert!(!s.contains("abc"), "{s}");
    }

    #[test]
    fn error_message_is_capped() {
        let e = CheckError::new(ErrorKind::Other, "é".repeat(1000));
        assert_eq!(e.message.chars().count(), MAX_ERROR_MESSAGE);
    }

    #[test]
    fn rfc3339_millis() {
        let t = time::macros::datetime!(2026-10-03 05:00:00.123456 UTC);
        assert_eq!(rfc3339(t), "2026-10-03T05:00:00.123Z");
    }

    #[test]
    fn versions() {
        assert_eq!(version_cmp("1.10.0", "1.9.3"), Some(Ordering::Greater));
        assert_eq!(version_cmp("1.0", "1.0.0"), Some(Ordering::Equal));
        assert_eq!(version_cmp("v2.0.0-rc.1", "1.9.9"), Some(Ordering::Greater));
        assert_eq!(version_cmp("x", "1"), None);
    }
}
