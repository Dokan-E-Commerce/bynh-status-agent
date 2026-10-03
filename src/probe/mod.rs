//! Runs a single check and turns it into a protocol result.

pub mod rules;

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{HeaderMap, Method};
use time::OffsetDateTime;

use crate::details::{self, DetailTimings, Details, RedirectHop, RequestInfo};
use crate::net::{self, Capture, HttpRequest, Net, Trace};
use crate::netguard::Guard;
use crate::protocol::{rfc3339, Auth, Check, CheckError, CheckResult, CheckType, ErrorKind};
use crate::proxy::{ProxyEndpoint, ProxySettings};

/// Maximum number of response body bytes read per request.
pub const MAX_BODY: usize = 1 << 20;
/// Upper bound on a check's timeout, whatever the platform sends.
pub const MAX_TIMEOUT_MS: u64 = 120_000;

/// A body sample is sent again at least this often per check, even when
/// the body hasn't changed.
pub const SAMPLE_REFRESH: Duration = Duration::from_secs(3600);

pub struct Prober {
    /// Per check id: SHA-256 of the body of the last sample sent, and when.
    /// Bounded by the number of assigned checks; entries go when a check is
    /// unassigned.
    samples: std::sync::Mutex<std::collections::HashMap<String, (String, Instant)>>,
    sample_refresh: Duration,
    net: Arc<Net>,
    guard: Guard,
    report_ip: bool,
    /// Set only with `check_via_proxy = true`.
    proxy: Option<Arc<ProxySettings>>,
}

#[derive(Default)]
struct Outcome {
    /// The last request (or connection) made.
    trace: Trace,
    status_code: Option<u16>,
    response_bytes: Option<u64>,
    /// The request as configured (http and keyword checks).
    request: Option<RequestInfo>,
    /// Redirects followed, in order.
    redirects: Vec<RedirectHop>,
    /// Whole tcp/tls check, connection and handshake.
    total_ms: Option<u64>,
}

fn other(msg: impl Into<String>) -> CheckError {
    CheckError::new(ErrorKind::Other, msg)
}

impl Prober {
    pub fn new(net: Arc<Net>, guard: Guard, report_ip: bool) -> Self {
        Self {
            samples: Default::default(),
            sample_refresh: SAMPLE_REFRESH,
            net,
            guard,
            report_ip,
            proxy: None,
        }
    }

    /// Changes how often an unchanged body is sampled again (tests).
    pub fn with_sample_refresh(mut self, every: Duration) -> Self {
        self.sample_refresh = every;
        self
    }

    /// Forgets the last sample sent for `check_id` (the check was unassigned).
    pub fn forget(&self, check_id: &str) {
        self.samples
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(check_id);
    }

    /// Sends the body sample only when it is useful: the check failed, the
    /// body changed since the last sample sent, the last one is older than
    /// [`SAMPLE_REFRESH`], or none was sent yet. Otherwise the sample is
    /// replaced by `sample_omitted: "unchanged"`.
    fn dedupe_sample(&self, check_id: &str, failed: bool, details: &mut Details) {
        let Some(body) = details.body.as_mut() else {
            return;
        };
        let (Some(_), Some(sha)) = (&body.sample, &body.sha256) else {
            return; // capture_body = false, or nothing to compare
        };
        let mut map = self.samples.lock().unwrap_or_else(|e| e.into_inner());
        let send = failed
            || match map.get(check_id) {
                None => true,
                Some((last, at)) => last != sha || at.elapsed() >= self.sample_refresh,
            };
        if send {
            map.insert(check_id.to_owned(), (sha.clone(), Instant::now()));
        } else {
            body.sample = None;
            body.sample_base64 = false;
            body.sample_omitted = Some(details::SAMPLE_UNCHANGED);
        }
    }

    /// Send checks through an outbound proxy (`check_via_proxy`). Through a
    /// proxy the agent can't vet the final address, so callers must only do
    /// this with `allow_private = true`.
    pub fn with_proxy(mut self, proxy: ProxySettings) -> Self {
        self.proxy = (!proxy.is_empty()).then(|| Arc::new(proxy));
        self
    }

    fn proxy_for_host(&self, host: &str) -> Option<&ProxyEndpoint> {
        self.proxy.as_deref().and_then(|p| p.for_host(host, true))
    }

    /// Runs `check` once, bounded by its timeout. Never panics, never fails:
    /// every problem becomes a result with `ok = false`.
    pub async fn run(&self, check: &Check) -> CheckResult {
        let started_at = OffsetDateTime::now_utc();
        let start = Instant::now();
        let timeout_ms = check.timeout_ms.clamp(1, MAX_TIMEOUT_MS);
        let mut out = Outcome::default();
        let res = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            self.execute(check, &mut out),
        )
        .await;
        let error = match res {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e),
            Err(_) => Some(CheckError::new(
                ErrorKind::Timeout,
                format!("no complete response within {timeout_ms} ms"),
            )),
        };
        let t = &out.trace.timings;
        let has_timings = t.dns_ms.is_some()
            || t.connect_ms.is_some()
            || t.tls_ms.is_some()
            || t.ttfb_ms.is_some();
        let mut details = self.details(check, &mut out);
        self.dedupe_sample(&check.id, error.is_some(), &mut details);
        let mut result = CheckResult {
            check_id: check.id.clone(),
            started_at: rfc3339(started_at),
            duration_ms: net::ms(start.elapsed()),
            ok: error.is_none(),
            status_code: out.status_code,
            error,
            timings: has_timings.then(|| out.trace.timings.clone()),
            tls_expires_at: out.trace.tls_expires_at.map(rfc3339),
            remote_ip: if self.report_ip {
                out.trace.remote_ip.map(|ip| ip.to_string())
            } else {
                None
            },
            response_bytes: out.response_bytes,
            details: Some(details),
            confirm_nonce: None,
        };
        details::fit_budget(&mut result, details::MAX_RESULT_BYTES);
        result
    }

    /// Check details from what was gathered, up to the phase that failed.
    fn details(&self, check: &Check, out: &mut Outcome) -> Details {
        let trace = &out.trace;
        let response = trace.response.as_ref();
        let t = &trace.timings;
        let timings = DetailTimings {
            dns_ms: t.dns_ms,
            connect_ms: t.connect_ms,
            tls_ms: t.tls_ms,
            ttfb_ms: t.ttfb_ms,
            download_ms: trace.download_ms,
            total_ms: trace.total_ms.or(out.total_ms),
        };
        let skip = out.redirects.len().saturating_sub(details::MAX_REDIRECTS);
        Details {
            http_version: response.and_then(|r| r.http_version),
            ip_family: trace.remote_ip.map(details::ip_family),
            request: out.request.take(),
            status_text: response.and_then(|r| r.status_text.clone()),
            response_headers: response.map(|r| r.headers.clone()).unwrap_or_default(),
            body: trace
                .body
                .as_ref()
                .map(|b| b.finish(response.and_then(|r| r.content_type.clone()))),
            redirects: out.redirects.drain(skip..).collect(),
            tls: trace.tls.clone(),
            timings: (!timings.is_empty()).then_some(timings),
        }
        .with_capture(check.capture_body)
    }

    async fn execute(&self, check: &Check, out: &mut Outcome) -> Result<(), CheckError> {
        match check.kind {
            CheckType::Http | CheckType::Keyword => self.http(check, out).await,
            CheckType::Tcp => self.tcp(check, out).await,
            CheckType::Tls => self.tls(check, out).await,
        }
    }

    async fn http(&self, check: &Check, out: &mut Outcome) -> Result<(), CheckError> {
        let raw = check
            .url
            .as_deref()
            .ok_or_else(|| other("check has no url"))?;
        let mut url = url::Url::parse(raw).map_err(|e| other(format!("invalid url: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(other(format!("unsupported URL scheme {:?}", url.scheme())));
        }

        let mut auth = check.auth.clone();
        if auth.is_none() && !url.username().is_empty() {
            let dec = |s: &str| percent_decode(s);
            auth = Some(Auth::Basic {
                username: dec(url.username()),
                password: dec(url.password().unwrap_or("")),
            });
        }
        let _ = url.set_username("");
        let _ = url.set_password(None);

        let upper = check.method.trim().to_ascii_uppercase();
        if !crate::protocol::METHODS.contains(&upper.as_str()) {
            return Err(other("method not allowed"));
        }
        let mut method =
            Method::from_bytes(upper.as_bytes()).map_err(|_| other("invalid method"))?;
        let mut headers = build_headers(check)?;
        if check.kind == CheckType::Keyword {
            // The keyword is matched against the raw bytes, so ask for them.
            headers.insert(
                header::ACCEPT_ENCODING,
                HeaderValue::from_static("identity"),
            );
        }
        if let Some(a) = &auth {
            headers.insert(header::AUTHORIZATION, auth_header(a)?);
        }
        let mut body = check.body.clone().map(Bytes::from);
        let keyword = match check.kind {
            CheckType::Keyword => Some(
                check
                    .keyword
                    .as_deref()
                    .filter(|k| !k.is_empty())
                    .ok_or_else(|| other("keyword check has no keyword"))?,
            ),
            _ => None,
        };

        out.request = Some(RequestInfo {
            method: upper.clone(),
            url: details::cap(url.as_str(), details::MAX_URL),
        });
        let capture = if check.capture_body {
            Capture::Sample
        } else {
            Capture::Metadata
        };
        let mut hops = 0u32;
        loop {
            out.trace = Trace::default();
            out.status_code = None;
            out.response_bytes = None;
            let resp = self
                .net
                .http(
                    HttpRequest {
                        url: &url,
                        method: method.clone(),
                        headers: &headers,
                        body: body.clone(),
                        verify_tls: check.verify_tls,
                        ip_version: check.ip_version,
                        guard: &self.guard,
                        proxy: self.proxy.as_deref().and_then(|p| p.for_url(&url)),
                        max_body: MAX_BODY,
                        keep_body: keyword.is_some(),
                        capture,
                    },
                    &mut out.trace,
                )
                .await?;
            out.status_code = Some(resp.status);
            out.response_bytes = Some(resp.body_len);

            if check.follow_redirects && rules::is_redirect(resp.status) {
                if let Some(location) = resp.headers.get(header::LOCATION) {
                    if hops >= check.max_redirects {
                        return Err(CheckError::new(
                            ErrorKind::Redirects,
                            format!("more than {} redirects", check.max_redirects),
                        ));
                    }
                    // Non-ASCII bytes are tolerated; the URL parser
                    // percent-encodes them.
                    let location = String::from_utf8_lossy(location.as_bytes());
                    let mut next = url.join(location.trim()).map_err(|e| {
                        CheckError::new(
                            ErrorKind::Redirects,
                            format!("invalid redirect target: {e}"),
                        )
                    })?;
                    if !matches!(next.scheme(), "http" | "https") {
                        return Err(CheckError::new(
                            ErrorKind::Redirects,
                            format!("redirect to unsupported scheme {:?}", next.scheme()),
                        ));
                    }
                    // Credentials in a Location are never followed or passed on
                    // (they would reach a proxy in absolute-form requests).
                    let _ = next.set_username("");
                    let _ = next.set_password(None);
                    let (m, keep_body) = rules::redirect_method(resp.status, &method);
                    if !keep_body {
                        body = None;
                        headers.remove(header::CONTENT_TYPE);
                    }
                    if rules::crosses_origin(&url, &next) {
                        headers = rules::cross_origin_headers(&headers, keep_body);
                    }
                    out.redirects.push(RedirectHop {
                        url: details::cap(next.as_str(), details::MAX_URL),
                        status: resp.status,
                        duration_ms: out.trace.total_ms.unwrap_or(0),
                        remote_ip: self.reported_ip(&out.trace),
                    });
                    method = m;
                    url = next;
                    hops += 1;
                    continue;
                }
            }

            if !rules::status_matches(resp.status, &check.expected_statuses) {
                return Err(CheckError::new(
                    ErrorKind::Status,
                    format!("unexpected status {}", resp.status),
                ));
            }
            if let Some(kw) = keyword {
                let found = rules::keyword_found(&resp.body, kw);
                if check.keyword_absent && found {
                    return Err(CheckError::new(
                        ErrorKind::Keyword,
                        "keyword is present in the response body",
                    ));
                }
                if !check.keyword_absent && !found {
                    return Err(CheckError::new(
                        ErrorKind::Keyword,
                        "keyword not found in the first 1 MiB of the response body",
                    ));
                }
            }
            return Ok(());
        }
    }

    fn reported_ip(&self, trace: &Trace) -> Option<String> {
        if self.report_ip {
            trace.remote_ip.map(|ip| ip.to_string())
        } else {
            None
        }
    }

    async fn tcp(&self, check: &Check, out: &mut Outcome) -> Result<(), CheckError> {
        let start = Instant::now();
        let r = self.tcp_inner(check, out).await;
        out.total_ms = Some(net::ms(start.elapsed()));
        r
    }

    async fn tls(&self, check: &Check, out: &mut Outcome) -> Result<(), CheckError> {
        let start = Instant::now();
        let r = self.tls_inner(check, out).await;
        out.total_ms = Some(net::ms(start.elapsed()));
        r
    }

    async fn tcp_inner(&self, check: &Check, out: &mut Outcome) -> Result<(), CheckError> {
        let (host, port) = host_port(check, None)?;
        let proxy = self.proxy_for_host(&host);
        self.net
            .connect_target(
                &host,
                port,
                check.ip_version,
                &self.guard,
                proxy,
                &mut out.trace,
            )
            .await?;
        Ok(())
    }

    async fn tls_inner(&self, check: &Check, out: &mut Outcome) -> Result<(), CheckError> {
        let (host, port) = host_port(check, Some(443))?;
        let proxy = self.proxy_for_host(&host);
        let tcp = self
            .net
            .connect_target(
                &host,
                port,
                check.ip_version,
                &self.guard,
                proxy,
                &mut out.trace,
            )
            .await?;
        if let Err(e) = self
            .net
            .tls_handshake(tcp, &host, check.verify_tls, &mut out.trace)
            .await
        {
            // An expired or untrusted certificate still reports when it
            // expires: the verifier saw it before the handshake failed.
            out.trace.tls_expires_at = out.trace.peer_not_after;
            return Err(e);
        }
        match out.trace.tls_expires_at {
            Some(exp) if exp <= OffsetDateTime::now_utc() => Err(CheckError::new(
                ErrorKind::Tls,
                format!("certificate expired at {}", rfc3339(exp)),
            )),
            Some(_) => Ok(()),
            None => Err(CheckError::new(
                ErrorKind::Tls,
                "could not read the server certificate",
            )),
        }
    }
}

/// Target of a tcp/tls check: `host` + `port`, or the host and port of `url`.
fn host_port(check: &Check, default_port: Option<u16>) -> Result<(String, u16), CheckError> {
    if let Some(host) = check.host.as_deref().filter(|h| !h.is_empty()) {
        let host = net::normalize_host(host)?;
        let port = check
            .port
            .or(default_port)
            .ok_or_else(|| other("check has no port"))?;
        return Ok((host, port));
    }
    if let Some(raw) = check.url.as_deref() {
        let url = url::Url::parse(raw).map_err(|e| other(format!("invalid url: {e}")))?;
        let host = net::host_of(&url)?;
        let port = url
            .port_or_known_default()
            .or(check.port)
            .or(default_port)
            .ok_or_else(|| other("check has no port"))?;
        return Ok((host, port));
    }
    Err(other("check has no host"))
}

/// Headers a monitor may not set: they control framing or the connection
/// and could desynchronise the request.
fn is_forbidden_header(name: &HeaderName) -> bool {
    let n = name.as_str();
    matches!(
        n,
        "content-length"
            | "transfer-encoding"
            | "te"
            | "upgrade"
            | "expect"
            | "keep-alive"
            | "connection"
            | "host"
            | "trailer"
    ) || n.starts_with("proxy-")
}

fn build_headers(check: &Check) -> Result<HeaderMap, CheckError> {
    let mut map = HeaderMap::new();
    for (k, v) in &check.headers {
        let name = HeaderName::from_bytes(k.trim().as_bytes())
            .map_err(|_| other("invalid header name"))?;
        if is_forbidden_header(&name) {
            continue;
        }
        let mut value = HeaderValue::from_str(v).map_err(|_| other("invalid header value"))?;
        value.set_sensitive(true);
        map.append(name, value);
    }
    Ok(map)
}

fn auth_header(auth: &Auth) -> Result<HeaderValue, CheckError> {
    let raw = match auth {
        Auth::Basic { username, password } => format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
        ),
        Auth::Bearer { token } => format!("Bearer {token}"),
    };
    let mut v = HeaderValue::from_str(&raw).map_err(|_| other("invalid auth credentials"))?;
    v.set_sensitive(true);
    Ok(v)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_userinfo() {
        assert_eq!(percent_decode("p%40ss%3Aword"), "p@ss:word");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("bad%zz%4"), "bad%zz%4");
    }

    #[test]
    fn host_port_sources() {
        let mut c = Check::new("t", CheckType::Tcp);
        c.host = Some("db.internal".into());
        c.port = Some(5432);
        assert_eq!(host_port(&c, None).unwrap(), ("db.internal".into(), 5432));
        let mut c = Check::new("t", CheckType::Tls);
        c.url = Some("https://[2001:db8::1]:8443/x".into());
        assert_eq!(
            host_port(&c, Some(443)).unwrap(),
            ("2001:db8::1".into(), 8443)
        );
        let mut c = Check::new("t", CheckType::Tls);
        c.host = Some("example.com".into());
        assert_eq!(
            host_port(&c, Some(443)).unwrap(),
            ("example.com".into(), 443)
        );
        let mut c = Check::new("t", CheckType::Tcp);
        c.host = Some("example.com".into());
        assert!(host_port(&c, None).is_err());
    }

    #[test]
    fn bearer_header_is_sensitive() {
        let v = auth_header(&Auth::Bearer { token: "t".into() }).unwrap();
        assert!(v.is_sensitive());
        let v = auth_header(&Auth::Basic {
            username: "u".into(),
            password: "p".into(),
        })
        .unwrap();
        assert_eq!(v.to_str().unwrap(), "Basic dTpw");
    }
}
