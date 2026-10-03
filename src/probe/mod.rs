//! Runs a single check and turns it into a protocol result.

pub mod rules;

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{HeaderMap, Method};
use time::OffsetDateTime;

use crate::net::{self, HttpRequest, Net, Trace};
use crate::netguard::Guard;
use crate::protocol::{rfc3339, Auth, Check, CheckError, CheckResult, CheckType, ErrorKind};

/// Maximum number of response body bytes read per request.
pub const MAX_BODY: usize = 1 << 20;
/// Upper bound on a check's timeout, whatever the platform sends.
pub const MAX_TIMEOUT_MS: u64 = 120_000;

pub struct Prober {
    net: Arc<Net>,
    guard: Guard,
    report_ip: bool,
}

#[derive(Default)]
struct Outcome {
    trace: Trace,
    status_code: Option<u16>,
    response_bytes: Option<u64>,
}

fn other(msg: impl Into<String>) -> CheckError {
    CheckError::new(ErrorKind::Other, msg)
}

impl Prober {
    pub fn new(net: Arc<Net>, guard: Guard, report_ip: bool) -> Self {
        Self {
            net,
            guard,
            report_ip,
        }
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
        CheckResult {
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
        }
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

        let mut method = Method::from_bytes(check.method.trim().to_ascii_uppercase().as_bytes())
            .map_err(|_| other("invalid method"))?;
        let mut headers = build_headers(check)?;
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

        let mut hops = 0u32;
        loop {
            out.trace = Trace::default();
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
                        max_body: MAX_BODY,
                    },
                    &mut out.trace,
                )
                .await?;
            out.status_code = Some(resp.status);
            out.response_bytes = Some(resp.body.len() as u64);

            if check.follow_redirects && rules::is_redirect(resp.status) {
                if let Some(location) = resp.headers.get(header::LOCATION) {
                    if hops >= check.max_redirects {
                        return Err(CheckError::new(
                            ErrorKind::Redirects,
                            format!("more than {} redirects", check.max_redirects),
                        ));
                    }
                    let location = location.to_str().map_err(|_| {
                        CheckError::new(ErrorKind::Redirects, "invalid Location header")
                    })?;
                    let next = url.join(location).map_err(|e| {
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
                    if rules::crosses_origin(&url, &next) {
                        headers.remove(header::AUTHORIZATION);
                        headers.remove(header::PROXY_AUTHORIZATION);
                        headers.remove(header::COOKIE);
                    }
                    let (m, keep_body) = rules::redirect_method(resp.status, &method);
                    if !keep_body {
                        body = None;
                        headers.remove(header::CONTENT_TYPE);
                    }
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

    async fn tcp(&self, check: &Check, out: &mut Outcome) -> Result<(), CheckError> {
        let (host, port) = host_port(check, None)?;
        self.net
            .connect(&host, port, check.ip_version, &self.guard, &mut out.trace)
            .await?;
        Ok(())
    }

    async fn tls(&self, check: &Check, out: &mut Outcome) -> Result<(), CheckError> {
        let (host, port) = host_port(check, Some(443))?;
        let tcp = self
            .net
            .connect(&host, port, check.ip_version, &self.guard, &mut out.trace)
            .await?;
        if let Err(e) = self
            .net
            .tls_handshake(tcp, &host, check.verify_tls, &mut out.trace)
            .await
        {
            if check.verify_tls {
                // Learn the expiry anyway, so an expired or untrusted certificate
                // still reports when it expires.
                let mut probe = Trace::default();
                if let Ok(tcp) = self
                    .net
                    .connect(&host, port, check.ip_version, &self.guard, &mut probe)
                    .await
                {
                    if self
                        .net
                        .tls_handshake(tcp, &host, false, &mut probe)
                        .await
                        .is_ok()
                    {
                        out.trace.tls_expires_at = probe.tls_expires_at;
                    }
                }
            }
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
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
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

fn build_headers(check: &Check) -> Result<HeaderMap, CheckError> {
    let mut map = HeaderMap::new();
    for (k, v) in &check.headers {
        let name = HeaderName::from_bytes(k.trim().as_bytes())
            .map_err(|_| other(format!("invalid header name {k:?}")))?;
        let value = HeaderValue::from_str(v)
            .map_err(|_| other(format!("invalid value for header {name}")))?;
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
