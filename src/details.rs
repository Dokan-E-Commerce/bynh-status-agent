//! Check details sent with every result (agent 1.1.0, see "Check details" in
//! `PROTOCOL.md`): response metadata, a body sample, redirect hops, TLS
//! details and extra timings. Everything here is bounded, and response
//! header values that can carry credentials are redacted before they leave
//! the agent.

use std::fmt;
use std::net::IpAddr;

use base64::Engine as _;
use http::HeaderMap;
use serde::Serialize;
use time::OffsetDateTime;

use crate::protocol::{rfc3339, CheckResult};

/// Largest serialised result (with details) the agent sends, in bytes.
pub const MAX_RESULT_BYTES: usize = 128 * 1024;
/// Largest body sample, in bytes of the `sample` string.
pub const SAMPLE_MAX: usize = 64 * 1024;
/// Raw bytes that fit in [`SAMPLE_MAX`] once base64-encoded.
pub const SAMPLE_RAW_BASE64: usize = SAMPLE_MAX / 4 * 3;
/// Response headers kept, at most.
pub const MAX_HEADERS: usize = 100;
/// Longest response header value kept, in bytes.
pub const MAX_HEADER_VALUE: usize = 2 * 1024;
/// Total size of the kept response headers (names and values), in bytes.
pub const MAX_HEADERS_TOTAL: usize = 32 * 1024;
/// Redirect hops reported, at most (the last ones are kept).
pub const MAX_REDIRECTS: usize = 10;
/// Subject alternative names reported, at most.
pub const MAX_SANS: usize = 100;
/// Longest URL reported (request and redirect targets), in bytes.
pub const MAX_URL: usize = 8 * 1024;
/// Longest certificate name, SAN, status text or content type, in bytes.
const MAX_NAME: usize = 1024;
const MAX_SAN: usize = 255;
const MAX_SHORT: usize = 256;
/// Replacement for redacted header values.
pub const REDACTED: &str = "[redacted]";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Details {
    pub http_version: Option<&'static str>,
    pub ip_family: Option<&'static str>,
    pub request: Option<RequestInfo>,
    pub status_text: Option<String>,
    /// `[name, value]` pairs, names lowercased, values redacted where needed.
    pub response_headers: Vec<(String, String)>,
    pub body: Option<BodyDetails>,
    pub redirects: Vec<RedirectHop>,
    pub tls: Option<TlsDetails>,
    pub timings: Option<DetailTimings>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestInfo {
    pub method: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BodyDetails {
    pub sample: Option<String>,
    pub sample_base64: bool,
    pub truncated: bool,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    pub content_type: Option<String>,
    /// `"unchanged"` when the sample was left out because the body is the
    /// same as the last sample sent for this check within the hour.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_omitted: Option<&'static str>,
}

/// Value of `sample_omitted` for a body identical to the last sample sent.
pub const SAMPLE_UNCHANGED: &str = "unchanged";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedirectHop {
    /// Where this hop redirected to (the next URL requested).
    pub url: String,
    /// The redirect status this hop answered with.
    pub status: u16,
    pub duration_ms: u64,
    /// Omitted with `report_ip = false` and through a proxy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsDetails {
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub sans: Vec<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub fingerprint_sha256: Option<String>,
    pub chain_length: usize,
    pub verified: bool,
    pub verify_error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DetailTimings {
    pub dns_ms: Option<u64>,
    pub connect_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub download_ms: Option<u64>,
    pub total_ms: Option<u64>,
}

impl Details {
    /// Applies `capture_body = false`: the body sample is never sent.
    pub fn with_capture(mut self, capture_body: bool) -> Self {
        if !capture_body {
            if let Some(b) = self.body.as_mut() {
                b.sample = None;
                b.sample_base64 = false;
            }
        }
        self
    }
}

impl DetailTimings {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

// ---------------------------------------------------------------------------
// Response headers

/// Headers whose values are always redacted.
pub const REDACT_ALWAYS: &[&str] = &[
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "cookie",
    "www-authenticate",
];
/// Any header whose name contains one of these is redacted ...
pub const REDACT_PARTS: &[&str] = &[
    "token",
    "secret",
    "key",
    "session",
    "auth",
    "password",
    "signature",
];
/// ... except these.
pub const REDACT_EXEMPT: &[&str] = &[
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "keep-alive",
    "accept-ranges",
];

/// True if the value of response header `name` must not leave the agent.
/// Case-insensitive.
pub fn is_redacted_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if REDACT_ALWAYS.contains(&n.as_str()) {
        return true;
    }
    if REDACT_EXEMPT.contains(&n.as_str()) {
        return false;
    }
    REDACT_PARTS.iter().any(|p| n.contains(p))
}

/// Response headers in received order (repeats of a name grouped after its
/// first occurrence), redacted and bounded: at most [`MAX_HEADERS`] headers,
/// values cut to [`MAX_HEADER_VALUE`] bytes, [`MAX_HEADERS_TOTAL`] in all.
pub fn capture_headers(map: &HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut total = 0usize;
    for (name, value) in map {
        if out.len() >= MAX_HEADERS {
            break;
        }
        let name = name.as_str().to_ascii_lowercase();
        let value = if is_redacted_header(&name) {
            REDACTED.to_owned()
        } else {
            cap(&String::from_utf8_lossy(value.as_bytes()), MAX_HEADER_VALUE)
        };
        let len = name.len() + value.len();
        if total + len > MAX_HEADERS_TOTAL {
            break;
        }
        total += len;
        out.push((name, value));
    }
    out
}

/// `s` cut to at most `max` bytes on a character boundary, ending in `…`
/// when cut.
pub fn cap(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let ellipsis = '…'.len_utf8();
    let mut end = max.saturating_sub(ellipsis);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_owned();
    out.push('…');
    out
}

/// Status text: the reason phrase the server sent, else the standard one.
pub fn status_text(reason: Option<&[u8]>, status: http::StatusCode) -> Option<String> {
    match reason {
        Some(r) if !r.is_empty() => Some(cap(&String::from_utf8_lossy(r), MAX_SHORT)),
        _ => status.canonical_reason().map(str::to_owned),
    }
}

pub fn http_version(v: http::Version) -> Option<&'static str> {
    Some(match v {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2",
        http::Version::HTTP_3 => "HTTP/3",
        _ => return None,
    })
}

pub fn ip_family(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "4",
        IpAddr::V6(_) => "6",
    }
}

pub fn content_type(map: &HeaderMap) -> Option<String> {
    map.get(http::header::CONTENT_TYPE)
        .map(|v| cap(&String::from_utf8_lossy(v.as_bytes()), MAX_SHORT))
}

// ---------------------------------------------------------------------------
// Body

/// Streams a response body: keeps the first [`SAMPLE_MAX`] bytes (only when
/// sampling), counts and hashes everything read.
#[derive(Clone)]
pub struct BodyCapture {
    sample: Option<Vec<u8>>,
    hasher: ring::digest::Context,
    size: u64,
    /// More body followed what was read (the read cap was hit).
    more: bool,
}

impl fmt::Debug for BodyCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyCapture")
            .field("sampled", &self.sample.as_ref().map(Vec::len))
            .field("size", &self.size)
            .field("more", &self.more)
            .finish()
    }
}

impl BodyCapture {
    pub fn new(keep_sample: bool) -> Self {
        Self {
            sample: keep_sample.then(Vec::new),
            hasher: ring::digest::Context::new(&ring::digest::SHA256),
            size: 0,
            more: false,
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.size += data.len() as u64;
        if let Some(s) = &mut self.sample {
            let room = SAMPLE_MAX.saturating_sub(s.len());
            s.extend_from_slice(&data[..data.len().min(room)]);
        }
    }

    /// Marks that the body continued past the read cap.
    pub fn set_more(&mut self) {
        self.more = true;
    }

    /// The `body` details. `content_type` decides between a text and a
    /// base64 sample.
    pub fn finish(&self, content_type: Option<String>) -> BodyDetails {
        let sha256 = Some(hex(self.hasher.clone().finish().as_ref()));
        let longer_than = |n: usize| self.more || self.size > n as u64;
        let (sample, sample_base64, truncated) = match &self.sample {
            None => (None, false, longer_than(SAMPLE_MAX)),
            Some(raw) => {
                if is_text(content_type.as_deref(), raw) {
                    let cut = longer_than(raw.len());
                    let bytes = if cut { trim_partial_utf8(raw) } else { raw };
                    let mut text = String::from_utf8_lossy(bytes).into_owned();
                    // Replacement characters can make the text longer than the raw bytes.
                    let over = text.len() > SAMPLE_MAX;
                    if over {
                        let mut end = SAMPLE_MAX;
                        while !text.is_char_boundary(end) {
                            end -= 1;
                        }
                        text.truncate(end);
                    }
                    (Some(text), false, cut || over)
                } else {
                    let take = raw.len().min(SAMPLE_RAW_BASE64);
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&raw[..take]);
                    (Some(b64), true, longer_than(take))
                }
            }
        };
        BodyDetails {
            sample,
            sample_base64,
            truncated,
            size: Some(self.size),
            sha256,
            content_type,
            sample_omitted: None,
        }
    }
}

/// True when the sample can be sent as text: the content type is textual
/// (`text/*`, or mentions json, xml, javascript or html), or, with no
/// content type, the bytes are UTF-8 without NULs.
pub fn is_text(content_type: Option<&str>, raw: &[u8]) -> bool {
    match content_type {
        Some(ct) => {
            let mime = ct
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            mime.starts_with("text/")
                || ["json", "xml", "javascript", "html"]
                    .iter()
                    .any(|t| mime.contains(t))
        }
        None => !raw.contains(&0) && std::str::from_utf8(trim_partial_utf8(raw)).is_ok(),
    }
}

/// Drops an incomplete UTF-8 sequence at the end of a cut buffer, so a
/// sample cut mid-character doesn't end in a replacement character.
fn trim_partial_utf8(b: &[u8]) -> &[u8] {
    for back in 1..=3.min(b.len()) {
        let byte = b[b.len() - back];
        if byte & 0b1100_0000 == 0b1000_0000 {
            continue; // continuation byte
        }
        let need = match byte {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            _ => return b,
        };
        return if need > back { &b[..b.len() - back] } else { b };
    }
    b
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xF) as usize] as char);
    }
    s
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

// ---------------------------------------------------------------------------
// TLS

/// TLS details from the leaf certificate (DER). Also returns its notAfter.
/// Fields that can't be parsed are `null`; `fingerprint_sha256` is always set.
pub fn tls_details(
    leaf: &[u8],
    chain_length: usize,
    protocol: Option<rustls::ProtocolVersion>,
    cipher: Option<rustls::CipherSuite>,
    verify_error: Option<String>,
) -> (TlsDetails, Option<OffsetDateTime>) {
    let mut d = TlsDetails {
        protocol: protocol.map(protocol_name),
        cipher: cipher.map(|c| {
            c.as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{c:?}"))
        }),
        subject: None,
        issuer: None,
        sans: Vec::new(),
        not_before: None,
        not_after: None,
        fingerprint_sha256: Some(sha256_hex(leaf)),
        chain_length,
        verified: verify_error.is_none(),
        verify_error: verify_error
            .map(|e| crate::protocol::CheckError::new(crate::protocol::ErrorKind::Tls, e).message),
    };
    let mut expiry = None;
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(leaf) {
        d.subject = Some(cap(&dn(cert.subject()), MAX_NAME));
        d.issuer = Some(cap(&dn(cert.issuer()), MAX_NAME));
        let v = cert.validity();
        let nb = OffsetDateTime::from_unix_timestamp(v.not_before.timestamp()).ok();
        let na = OffsetDateTime::from_unix_timestamp(v.not_after.timestamp()).ok();
        d.not_before = nb.map(rfc3339);
        d.not_after = na.map(rfc3339);
        expiry = na;
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            use x509_parser::extensions::GeneralName;
            for name in &san.value.general_names {
                if d.sans.len() >= MAX_SANS {
                    break;
                }
                let s = match name {
                    GeneralName::DNSName(n) => cap(n, MAX_SAN),
                    GeneralName::IPAddress(b) => match b.len() {
                        4 => IpAddr::from(<[u8; 4]>::try_from(*b).unwrap()).to_string(),
                        16 => IpAddr::from(<[u8; 16]>::try_from(*b).unwrap()).to_string(),
                        _ => continue,
                    },
                    _ => continue,
                };
                d.sans.push(s);
            }
        }
    }
    (d, expiry)
}

fn protocol_name(p: rustls::ProtocolVersion) -> String {
    match p {
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".into(),
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".into(),
        rustls::ProtocolVersion::TLSv1_1 => "TLSv1.1".into(),
        rustls::ProtocolVersion::TLSv1_0 => "TLSv1.0".into(),
        other => format!("{other:?}"),
    }
}

/// A distinguished name in RFC 4514 order (most specific first), e.g.
/// `CN=R11, O=Let's Encrypt, C=US`.
fn dn(name: &x509_parser::x509::X509Name<'_>) -> String {
    let registry = x509_parser::objects::oid_registry();
    let rdns: Vec<_> = name.iter().collect();
    let mut out = String::new();
    for rdn in rdns.iter().rev() {
        for (i, attr) in rdn.iter().enumerate() {
            if !out.is_empty() {
                out.push_str(if i == 0 { ", " } else { " + " });
            }
            let oid = attr.attr_type();
            match x509_parser::objects::oid2abbrev(oid, registry) {
                Ok(abbrev) => out.push_str(abbrev),
                Err(_) => out.push_str(&oid.to_id_string()),
            }
            out.push('=');
            match attr.as_str() {
                Ok(v) => escape_dn_value(v, &mut out),
                Err(_) => {
                    out.push('#');
                    out.push_str(&hex(attr.attr_value().data));
                }
            }
        }
    }
    out
}

fn escape_dn_value(v: &str, out: &mut String) {
    let last = v.chars().count().saturating_sub(1);
    for (i, c) in v.chars().enumerate() {
        let special = matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';')
            || (i == 0 && (c == '#' || c == ' '))
            || (i == last && c == ' ');
        if special {
            out.push('\\');
        }
        if c.is_control() {
            out.push_str(&format!("\\{:02x}", c as u32));
        } else {
            out.push(c);
        }
    }
}

// ---------------------------------------------------------------------------
// Size budget

/// Bytes `value` takes as JSON, without allocating it.
pub fn json_len<T: Serialize + ?Sized>(value: &T) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut c = Count(0);
    let _ = serde_json::to_writer(&mut c, value);
    c.0
}

/// Shrinks `result` to at most `max` bytes of JSON: first the body sample,
/// then the response headers (from the end), then redirect hops (oldest
/// first) and SANs; as a last resort the details are dropped.
pub fn fit_budget(result: &mut CheckResult, max: usize) {
    let mut size = json_len(result);
    if size <= max {
        return;
    }
    if result.details.is_none() {
        return;
    }

    // 1. Body sample. Cut in proportion to how much JSON each sample byte
    // takes (escapes make it more than one), then measure again.
    while let Some(body) = result.details.as_mut().and_then(|d| d.body.as_mut()) {
        let base64 = body.sample_base64;
        let Some(sample) = body.sample.as_mut() else {
            break;
        };
        if sample.is_empty() {
            break;
        }
        let per_byte = (json_len(sample.as_str()) - 2) as f64 / sample.len() as f64;
        let cut = (((size - max) as f64 / per_byte).ceil() as usize).max(1);
        let mut keep = sample.len().saturating_sub(cut);
        if base64 {
            keep -= keep % 4;
        } else {
            while !sample.is_char_boundary(keep) {
                keep -= 1;
            }
        }
        sample.truncate(keep);
        body.truncated = true;
        size = json_len(result);
        if size <= max {
            return;
        }
    }

    // 2. Headers, from the end.
    let Some(d) = result.details.as_mut() else {
        return;
    };
    while let Some(pair) = d.response_headers.pop() {
        size = size.saturating_sub(json_len(&pair) + 1);
        if size <= max {
            break;
        }
    }
    size = json_len(result);
    if size <= max {
        return;
    }

    // 3. Redirect hops (oldest first), then SANs.
    let Some(d) = result.details.as_mut() else {
        return;
    };
    if !d.redirects.is_empty() {
        d.redirects.clear();
        size = json_len(result);
        if size <= max {
            return;
        }
    }
    let Some(d) = result.details.as_mut() else {
        return;
    };
    if let Some(t) = d.tls.as_mut() {
        t.sans.clear();
        size = json_len(result);
        if size <= max {
            return;
        }
    }

    // 4. Give up on details for this result.
    result.details = None;
}

/// Removes the body sample from a result (keeps size, hash and type).
/// Returns true if there was one.
pub fn strip_body_sample(result: &mut CheckResult) -> bool {
    match result
        .details
        .as_mut()
        .and_then(|d| d.body.as_mut())
        .filter(|b| b.sample.is_some())
    {
        Some(b) => {
            b.sample = None;
            b.sample_base64 = false;
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderName, HeaderValue};

    #[test]
    fn redaction_list() {
        for n in [
            "set-cookie",
            "Set-Cookie",
            "AUTHORIZATION",
            "proxy-authorization",
            "cookie",
            "WWW-Authenticate",
            "proxy-authenticate",
            "x-auth-token",
            "X-Api-Key",
            "x-session-id",
            "x-amz-security-token",
            "x-client-secret",
            "x-password-hint",
            "x-signature",
            "X-Hub-Signature-256",
            "public-key-pins",
        ] {
            assert!(is_redacted_header(n), "{n} not redacted");
        }
        for n in [
            "content-security-policy",
            "Strict-Transport-Security",
            "x-content-type-options",
            "keep-alive",
            "accept-ranges",
            "content-type",
            "server",
            "location",
            "etag",
            "cache-control",
        ] {
            assert!(!is_redacted_header(n), "{n} redacted");
        }
    }

    #[test]
    fn captured_headers_are_redacted_ordered_and_bounded() {
        let mut h = HeaderMap::new();
        h.append("content-type", HeaderValue::from_static("text/html"));
        h.append("set-cookie", HeaderValue::from_static("sid=hunter2"));
        h.append("set-cookie", HeaderValue::from_static("b=hunter3"));
        h.append("x-api-key", HeaderValue::from_static("hunter4"));
        h.append("server", HeaderValue::from_static("nginx"));
        let long = "v".repeat(5000);
        h.append("x-long", HeaderValue::from_str(&long).unwrap());
        let got = capture_headers(&h);
        let s = format!("{got:?}");
        assert!(!s.contains("hunter"), "{s}");
        assert_eq!(got[0], ("content-type".into(), "text/html".into()));
        assert_eq!(got[1], ("set-cookie".into(), REDACTED.into()));
        assert_eq!(got[2], ("set-cookie".into(), REDACTED.into()));
        assert_eq!(got[3], ("x-api-key".into(), REDACTED.into()));
        assert_eq!(got[4].0, "server");
        assert!(got[5].1.len() <= MAX_HEADER_VALUE && got[5].1.ends_with('…'));

        let mut many = HeaderMap::new();
        for i in 0..150 {
            many.append(
                HeaderName::from_bytes(format!("x-h{i}").as_bytes()).unwrap(),
                HeaderValue::from_static("1"),
            );
        }
        assert_eq!(capture_headers(&many).len(), MAX_HEADERS);

        let mut big = HeaderMap::new();
        for i in 0..40 {
            big.append(
                HeaderName::from_bytes(format!("x-b{i}").as_bytes()).unwrap(),
                HeaderValue::from_str(&"z".repeat(2000)).unwrap(),
            );
        }
        let got = capture_headers(&big);
        let total: usize = got.iter().map(|(n, v)| n.len() + v.len()).sum();
        assert!(total <= MAX_HEADERS_TOTAL && got.len() < 40, "{total}");
    }

    #[test]
    fn text_body_sample() {
        let mut b = BodyCapture::new(true);
        b.push(b"hello ");
        b.push("بينه".as_bytes());
        let d = b.finish(Some("text/plain; charset=utf-8".into()));
        assert_eq!(d.sample.as_deref(), Some("hello بينه"));
        assert!(!d.sample_base64 && !d.truncated);
        assert_eq!(d.size, Some(14));
        assert_eq!(d.sha256.unwrap(), sha256_hex("hello بينه".as_bytes()));
    }

    #[test]
    fn binary_body_is_base64() {
        let raw: Vec<u8> = (0..=255u8).collect();
        let mut b = BodyCapture::new(true);
        b.push(&raw);
        let d = b.finish(Some("image/png".into()));
        assert!(d.sample_base64);
        let back = base64::engine::general_purpose::STANDARD
            .decode(d.sample.unwrap())
            .unwrap();
        assert_eq!(back, raw);
        assert!(!d.truncated);
        // No content type: sniffed.
        let d = b.finish(None);
        assert!(d.sample_base64);
        let mut t = BodyCapture::new(true);
        t.push(b"{\"ok\":true}");
        assert!(!t.finish(None).sample_base64);
        assert!(
            !t.finish(Some("application/problem+json".into()))
                .sample_base64
        );
    }

    #[test]
    fn large_bodies_are_sampled_and_truncated() {
        let mut b = BodyCapture::new(true);
        let chunk = vec![b'a'; 10_000];
        for _ in 0..20 {
            b.push(&chunk);
        }
        let d = b.finish(Some("text/html".into()));
        assert_eq!(d.sample.as_ref().unwrap().len(), SAMPLE_MAX);
        assert!(d.truncated);
        assert_eq!(d.size, Some(200_000));

        let mut bin = BodyCapture::new(true);
        bin.push(&vec![0u8; 100_000]);
        let d = bin.finish(Some("application/octet-stream".into()));
        assert!(d.sample.as_ref().unwrap().len() <= SAMPLE_MAX);
        assert!(d.truncated);

        // A multi-byte character cut at the sample edge is dropped, not mangled.
        let mut u = BodyCapture::new(true);
        let mut s = vec![b'a'; SAMPLE_MAX - 1];
        s.extend_from_slice("é and more".as_bytes());
        u.push(&s);
        let d = u.finish(Some("text/plain".into()));
        let sample = d.sample.unwrap();
        assert!(!sample.contains('\u{FFFD}'));
        assert_eq!(sample.len(), SAMPLE_MAX - 1);
        assert!(d.truncated);
    }

    #[test]
    fn no_capture_keeps_metadata_only() {
        let mut b = BodyCapture::new(false);
        b.push(b"secret page");
        let d = b.finish(Some("text/html".into()));
        assert_eq!(d.sample, None);
        assert!(!d.sample_base64);
        assert_eq!(d.size, Some(11));
        assert!(d.sha256.is_some());
        assert_eq!(d.content_type.as_deref(), Some("text/html"));
    }

    fn result_with(details: Details) -> CheckResult {
        CheckResult {
            check_id: "mon_1".into(),
            started_at: "2026-10-03T05:00:00.000Z".into(),
            duration_ms: 1,
            ok: false,
            status_code: Some(200),
            error: None,
            timings: None,
            tls_expires_at: None,
            remote_ip: None,
            response_bytes: Some(1),
            details: Some(details),
        }
    }

    fn details() -> Details {
        Details {
            http_version: Some("HTTP/1.1"),
            ip_family: Some("4"),
            request: Some(RequestInfo {
                method: "GET".into(),
                url: "https://example.com/".into(),
            }),
            status_text: Some("OK".into()),
            response_headers: vec![],
            body: None,
            redirects: vec![],
            tls: None,
            timings: None,
        }
    }

    #[test]
    fn budget_truncates_the_body_sample_first() {
        let mut d = details();
        d.response_headers = (0..30)
            .map(|i| (format!("x-h{i}"), "v".repeat(1000)))
            .collect();
        let mut b = BodyCapture::new(true);
        // Control characters expand 6x in JSON.
        b.push(&vec![1u8; SAMPLE_MAX]);
        d.body = Some(b.finish(Some("text/plain".into())));
        let mut r = result_with(d);
        assert!(json_len(&r) > MAX_RESULT_BYTES);
        fit_budget(&mut r, MAX_RESULT_BYTES);
        assert!(json_len(&r) <= MAX_RESULT_BYTES, "{}", json_len(&r));
        let d = r.details.as_ref().unwrap();
        assert_eq!(d.response_headers.len(), 30, "headers kept");
        let body = d.body.as_ref().unwrap();
        assert!(body.truncated);
        assert!(body.sample.as_ref().unwrap().len() < SAMPLE_MAX);
    }

    #[test]
    fn budget_then_drops_headers() {
        let mut d = details();
        d.response_headers = (0..100)
            .map(|i| (format!("x-h{i}"), "\u{1}".repeat(300)))
            .collect();
        let mut b = BodyCapture::new(true);
        b.push(&vec![b'a'; SAMPLE_MAX]);
        d.body = Some(b.finish(Some("text/plain".into())));
        let mut r = result_with(d);
        fit_budget(&mut r, MAX_RESULT_BYTES);
        assert!(json_len(&r) <= MAX_RESULT_BYTES);
        let d = r.details.as_ref().unwrap();
        assert_eq!(d.body.as_ref().unwrap().sample.as_deref(), Some(""));
        assert!(d.response_headers.len() < 100 && !d.response_headers.is_empty());
        assert_eq!(d.response_headers[0].0, "x-h0", "kept from the start");

        // Small budgets fall back to dropping details altogether.
        let mut r = result_with(details());
        fit_budget(&mut r, 50);
        assert!(r.details.is_none());
    }

    #[test]
    fn base64_budget_cut_stays_decodable() {
        let mut d = details();
        let mut b = BodyCapture::new(true);
        b.push(&vec![0xFFu8; SAMPLE_RAW_BASE64]);
        d.body = Some(b.finish(Some("application/octet-stream".into())));
        let mut r = result_with(d);
        fit_budget(&mut r, 40_001);
        let s = r.details.unwrap().body.unwrap().sample.unwrap();
        assert_eq!(s.len() % 4, 0);
        assert!(base64::engine::general_purpose::STANDARD.decode(s).is_ok());
    }

    #[test]
    fn strips_samples() {
        let mut d = details();
        let mut b = BodyCapture::new(true);
        b.push(b"x");
        d.body = Some(b.finish(None));
        let mut r = result_with(d);
        assert!(strip_body_sample(&mut r));
        assert!(!strip_body_sample(&mut r));
        let body = r.details.unwrap().body.unwrap();
        assert!(body.sample.is_none() && body.size == Some(1) && body.sha256.is_some());
    }

    #[test]
    fn distinguished_names() {
        let mut params = rcgen::CertificateParams::new(vec![
            "shop.example.com".to_owned(),
            "www.shop.example.com".to_owned(),
        ])
        .unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress("203.0.113.5".parse().unwrap()));
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CountryName, "US");
        dn.push(rcgen::DnType::OrganizationName, "Example, Inc.");
        dn.push(rcgen::DnType::CommonName, "shop.example.com");
        params.distinguished_name = dn;
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let (d, exp) = tls_details(
            cert.der(),
            1,
            Some(rustls::ProtocolVersion::TLSv1_3),
            Some(rustls::CipherSuite::TLS13_AES_256_GCM_SHA384),
            Some("certificate issuer is not trusted".into()),
        );
        assert_eq!(d.protocol.as_deref(), Some("TLSv1.3"));
        assert_eq!(d.cipher.as_deref(), Some("TLS13_AES_256_GCM_SHA384"));
        assert_eq!(
            d.subject.as_deref(),
            Some("CN=shop.example.com, O=Example\\, Inc., C=US")
        );
        assert_eq!(d.issuer, d.subject);
        assert_eq!(
            d.sans,
            ["shop.example.com", "www.shop.example.com", "203.0.113.5"]
        );
        assert_eq!(d.fingerprint_sha256.unwrap(), sha256_hex(cert.der()));
        assert!(!d.verified);
        assert!(exp.is_some() && d.not_after.is_some() && d.not_before.is_some());
    }

    #[test]
    fn hex_and_cap() {
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
        assert_eq!(cap("abc", 3), "abc");
        assert_eq!(cap("abcdef", 5), "ab…");
        assert_eq!(cap("ééé", 5), "é…");
    }
}
