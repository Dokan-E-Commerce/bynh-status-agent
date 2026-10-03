//! Client for the bynh platform API (hello, assignments, results).

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use http::header::{self, HeaderValue};
use http::{HeaderMap, Method};

use crate::net::{HttpRequest, Net, Trace};
use crate::netguard::Guard;
use crate::protocol::{
    user_agent, Assignments, CheckResult, HelloRequest, HelloResponse, IpVersion, ResultsRequest,
    ResultsResponse, UpgradeRequired, PROTOCOL_VERSION,
};
use crate::proxy::ProxySettings;

/// Largest platform response we accept (compressed or not).
const MAX_RESPONSE: usize = 32 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// 401: the token was revoked or is wrong.
    Unauthorized,
    /// 426: this agent version is too old.
    UpgradeRequired {
        message: Option<String>,
        minimum_version: Option<String>,
    },
    /// 429, 5xx or a network failure: retry with backoff.
    Retryable {
        status: Option<u16>,
        retry_after: Option<Duration>,
        message: String,
    },
    /// Any other 4xx: the request itself is wrong.
    Rejected { status: u16, message: String },
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Unauthorized => f.write_str("401 unauthorized"),
            ApiError::UpgradeRequired {
                minimum_version, ..
            } => write!(
                f,
                "426 upgrade required (minimum version {})",
                minimum_version.as_deref().unwrap_or("unknown")
            ),
            ApiError::Retryable {
                status: Some(s),
                message,
                ..
            } => write!(f, "HTTP {s}: {message}"),
            ApiError::Retryable { message, .. } => f.write_str(message),
            ApiError::Rejected { status, message } => write!(f, "HTTP {status}: {message}"),
        }
    }
}

impl std::error::Error for ApiError {}

pub enum AssignmentsOutcome {
    NotModified,
    Changed {
        assignments: Assignments,
        etag: String,
    },
}

pub struct PlatformClient {
    net: Arc<Net>,
    base: String,
    token: String,
    timeout: Duration,
    guard: Guard,
    proxy: ProxySettings,
}

impl PlatformClient {
    pub fn new(net: Arc<Net>, base: &str, token: &str, timeout: Duration) -> Self {
        Self {
            net,
            base: base.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
            timeout,
            // The platform address is chosen by the operator, not by the
            // platform, so it may be local (self-hosting, tests).
            guard: Guard::new(true),
            proxy: ProxySettings::default(),
        }
    }

    /// Reach the platform through an outbound proxy (unless `no_proxy` matches).
    pub fn with_proxy(mut self, proxy: ProxySettings) -> Self {
        self.proxy = proxy;
        self
    }

    pub async fn hello(&self, req: &HelloRequest) -> Result<HelloResponse, ApiError> {
        let body = serde_json::to_vec(req).map_err(|e| decode_err(e.to_string()))?;
        let resp = self
            .send(Method::POST, "/api/v1/agent/hello", Some(body), false, None)
            .await?;
        expect(&resp, &[200])?;
        serde_json::from_slice(&resp.body).map_err(|e| decode_err(format!("hello response: {e}")))
    }

    pub async fn assignments(&self, etag: Option<&str>) -> Result<AssignmentsOutcome, ApiError> {
        let resp = self
            .send(Method::GET, "/api/v1/agent/assignments", None, false, etag)
            .await?;
        if resp.status == 304 {
            return Ok(AssignmentsOutcome::NotModified);
        }
        expect(&resp, &[200])?;
        let assignments = Assignments::parse(&resp.body)
            .map_err(|e| decode_err(format!("assignments response: {e}")))?;
        let etag = resp
            .headers
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("\"{}\"", assignments.config_version));
        Ok(AssignmentsOutcome::Changed { assignments, etag })
    }

    pub async fn results(&self, results: &[CheckResult]) -> Result<ResultsResponse, ApiError> {
        let body = serde_json::to_vec(&ResultsRequest { results })
            .map_err(|e| decode_err(e.to_string()))?;
        let resp = self
            .send(
                Method::POST,
                "/api/v1/agent/results",
                Some(body),
                true,
                None,
            )
            .await?;
        expect(&resp, &[200, 202])?;
        Ok(serde_json::from_slice(&resp.body).unwrap_or_default())
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        gzip: bool,
        if_none_match: Option<&str>,
    ) -> Result<Response, ApiError> {
        let url =
            url::Url::parse(&format!("{}{}", self.base, path)).map_err(|e| ApiError::Rejected {
                status: 0,
                message: format!("invalid api_url: {e}"),
            })?;
        let mut headers = HeaderMap::new();
        let mut auth = HeaderValue::from_str(&format!("Bearer {}", self.token))
            .map_err(|_| ApiError::Unauthorized)?;
        auth.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth);
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_str(&user_agent()).expect("ascii user agent"),
        );
        headers.insert(
            "x-bynh-status-agent-protocol",
            HeaderValue::from_static(PROTOCOL_VERSION),
        );
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        if let Some(tag) = if_none_match {
            if let Ok(v) = HeaderValue::from_str(tag) {
                headers.insert(header::IF_NONE_MATCH, v);
            }
        }
        let body = match body {
            Some(raw) => {
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                if gzip {
                    headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                    Some(Bytes::from(gzip_bytes(&raw)))
                } else {
                    Some(Bytes::from(raw))
                }
            }
            None => None,
        };

        let mut trace = Trace::default();
        let fut = self.net.http(
            HttpRequest {
                url: &url,
                method,
                headers: &headers,
                body,
                verify_tls: true,
                ip_version: IpVersion::Any,
                guard: &self.guard,
                proxy: self.proxy.for_url(&url),
                max_body: MAX_RESPONSE,
            },
            &mut trace,
        );
        let resp = match tokio::time::timeout(self.timeout, fut).await {
            Err(_) => {
                return Err(ApiError::Retryable {
                    status: None,
                    retry_after: None,
                    message: format!("request timed out after {:?}", self.timeout),
                })
            }
            Ok(Err(e)) => {
                return Err(ApiError::Retryable {
                    status: None,
                    retry_after: None,
                    message: e.message,
                })
            }
            Ok(Ok(r)) => r,
        };

        let gzipped = resp
            .headers
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("gzip"));
        let body = if gzipped {
            gunzip(&resp.body).map_err(|e| decode_err(format!("gzip response: {e}")))?
        } else {
            resp.body.to_vec()
        };
        Ok(Response {
            status: resp.status,
            headers: resp.headers,
            body,
        })
    }
}

struct Response {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

fn decode_err(message: String) -> ApiError {
    ApiError::Retryable {
        status: None,
        retry_after: None,
        message,
    }
}

/// Maps non-success statuses onto [`ApiError`].
fn expect(resp: &Response, ok: &[u16]) -> Result<(), ApiError> {
    if ok.contains(&resp.status) {
        return Ok(());
    }
    let snippet = || {
        let s = String::from_utf8_lossy(&resp.body);
        s.chars().take(200).collect::<String>()
    };
    Err(match resp.status {
        401 => ApiError::Unauthorized,
        426 => {
            let body: UpgradeRequired = serde_json::from_slice(&resp.body).unwrap_or_default();
            ApiError::UpgradeRequired {
                message: body.message,
                minimum_version: body.minimum_version,
            }
        }
        429 | 500..=599 => ApiError::Retryable {
            status: Some(resp.status),
            retry_after: resp
                .headers
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| parse_retry_after(v, SystemTime::now())),
            message: snippet(),
        },
        s => ApiError::Rejected {
            status: s,
            message: snippet(),
        },
    })
}

/// `Retry-After` as delta-seconds or an HTTP date.
pub fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let v = value.trim();
    if let Ok(secs) = v.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let at = httpdate::parse_http_date(v).ok()?;
    Some(at.duration_since(now).unwrap_or(Duration::ZERO))
}

pub fn gzip_bytes(raw: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(
        Vec::with_capacity(raw.len() / 4 + 64),
        flate2::Compression::default(),
    );
    // Writing to a Vec cannot fail.
    let _ = enc.write_all(raw);
    enc.finish().unwrap_or_default()
}

fn gunzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    GzDecoder::new(data)
        .take(MAX_RESPONSE as u64 + 1)
        .read_to_end(&mut out)?;
    if out.len() > MAX_RESPONSE {
        return Err(std::io::Error::other("decompressed response too large"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_forms() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert_eq!(
            parse_retry_after("120", now),
            Some(Duration::from_secs(120))
        );
        let later = httpdate::fmt_http_date(now + Duration::from_secs(30));
        assert_eq!(
            parse_retry_after(&later, now),
            Some(Duration::from_secs(30))
        );
        let past = httpdate::fmt_http_date(now - Duration::from_secs(30));
        assert_eq!(parse_retry_after(&past, now), Some(Duration::ZERO));
        assert_eq!(parse_retry_after("soon", now), None);
    }

    #[test]
    fn gzip_round_trip() {
        let raw = br#"{"results":[]}"#.repeat(100);
        let z = gzip_bytes(&raw);
        assert!(z.len() < raw.len());
        assert_eq!(gunzip(&z).unwrap(), raw);
    }

    fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
        let mut h = HeaderMap::new();
        for (k, v) in headers {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        Response {
            status,
            headers: h,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn status_mapping() {
        assert_eq!(
            expect(&resp(401, &[], ""), &[200]),
            Err(ApiError::Unauthorized)
        );
        assert_eq!(
            expect(
                &resp(
                    426,
                    &[],
                    r#"{"message":"too old","minimum_version":"1.2.0"}"#
                ),
                &[200]
            ),
            Err(ApiError::UpgradeRequired {
                message: Some("too old".into()),
                minimum_version: Some("1.2.0".into())
            })
        );
        match expect(&resp(429, &[("retry-after", "7")], ""), &[200]) {
            Err(ApiError::Retryable {
                status: Some(429),
                retry_after: Some(d),
                ..
            }) => assert_eq!(d, Duration::from_secs(7)),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            expect(&resp(503, &[], ""), &[200]),
            Err(ApiError::Retryable {
                status: Some(503),
                retry_after: None,
                ..
            })
        ));
        assert!(matches!(
            expect(&resp(413, &[], ""), &[200]),
            Err(ApiError::Rejected { status: 413, .. })
        ));
        assert!(expect(&resp(202, &[], ""), &[200, 202]).is_ok());
    }
}
