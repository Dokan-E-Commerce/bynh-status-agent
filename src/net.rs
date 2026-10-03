//! Low-level networking with per-phase timings: DNS (resolved once, then the
//! vetted IP is used for the connection, so DNS rebinding can't swap the
//! target), TCP connect, TLS handshake and a single HTTP/1.1 exchange.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use hickory_resolver::config::{LookupIpStrategy, ResolverConfig, CLOUDFLARE};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use http::{header, HeaderMap, HeaderValue, Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::Resumption;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::netguard::Guard;
use crate::protocol::{CheckError, ErrorKind, IpVersion, Timings};
use crate::proxy::ProxyEndpoint;

/// Shared networking context: one DNS resolver and the two TLS configurations.
pub struct Net {
    resolver: TokioResolver,
    tls_verify: Arc<ClientConfig>,
    tls_insecure: Arc<ClientConfig>,
}

/// What we learned about a connection while making it. Filled progressively,
/// so partial data survives an error or a timeout.
#[derive(Debug, Default, Clone)]
pub struct Trace {
    pub timings: Timings,
    pub remote_ip: Option<IpAddr>,
    pub tls_expires_at: Option<OffsetDateTime>,
}

/// One HTTP request to one URL (no redirect handling here).
pub struct HttpRequest<'a> {
    pub url: &'a url::Url,
    pub method: Method,
    pub headers: &'a HeaderMap,
    pub body: Option<Bytes>,
    pub verify_tls: bool,
    pub ip_version: IpVersion,
    pub guard: &'a Guard,
    /// Send the request through this proxy (CONNECT for https, absolute-form
    /// for http). The private-address guard then applies to the proxy.
    pub proxy: Option<&'a ProxyEndpoint>,
    /// Read at most this many body bytes; the rest is discarded unread.
    pub max_body: usize,
    /// Keep the body in memory (keyword checks, platform responses). When
    /// false the bytes are only counted.
    pub keep_body: bool,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HeaderMap,
    /// The body, if `keep_body` was set (at most `max_body` bytes).
    pub body: Bytes,
    /// Body bytes read (at most `max_body`), whether kept or not.
    pub body_len: u64,
}

pub(crate) fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl Net {
    /// Builds the resolver (system configuration, falling back to Cloudflare
    /// DNS if none is readable) and TLS configurations. `ca_file` adds PEM
    /// roots on top of the bundled Mozilla roots, for internal CAs.
    pub fn new(ca_file: Option<&Path>) -> Result<Self, String> {
        let (tls_verify, tls_insecure) = tls_configs(ca_file)?;
        Ok(Self {
            resolver: build_resolver()?,
            tls_verify,
            tls_insecure,
        })
    }

    /// Resolves `host` (a name or an IP literal, without brackets) once and
    /// returns the address to use, plus the DNS time in ms.
    pub async fn resolve(&self, host: &str, ipv: IpVersion) -> Result<(IpAddr, u64), CheckError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return match (ipv, ip) {
                (IpVersion::V4, IpAddr::V6(_)) | (IpVersion::V6, IpAddr::V4(_)) => Err(
                    CheckError::new(ErrorKind::Dns, "address family does not match ip_version"),
                ),
                _ => Ok((ip, 0)),
            };
        }
        let start = Instant::now();
        let lookup = self.resolver.lookup_ip(host).await.map_err(|e| {
            let msg = if e.is_nx_domain() {
                "host not found (NXDOMAIN)".to_owned()
            } else if e.is_no_records_found() {
                "no address records for host".to_owned()
            } else {
                format!("lookup failed: {e}")
            };
            CheckError::new(ErrorKind::Dns, msg)
        })?;
        let elapsed = ms(start.elapsed());
        let ips: Vec<IpAddr> = lookup.iter().collect();
        pick_address(&ips, ipv)
            .map(|ip| (ip, elapsed))
            .ok_or_else(|| {
                let fam = match ipv {
                    IpVersion::Any => "",
                    IpVersion::V4 => "IPv4 ",
                    IpVersion::V6 => "IPv6 ",
                };
                CheckError::new(ErrorKind::Dns, format!("no {fam}address found"))
            })
    }

    /// Resolves, vets and connects. Fills `trace.timings.dns_ms/connect_ms`
    /// and `trace.remote_ip`.
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
        ipv: IpVersion,
        guard: &Guard,
        trace: &mut Trace,
    ) -> Result<TcpStream, CheckError> {
        let (ip, dns_ms) = self.resolve(host, ipv).await?;
        trace.timings.dns_ms = Some(dns_ms);
        guard.check(ip)?;
        trace.remote_ip = Some(ip);
        let start = Instant::now();
        let tcp = TcpStream::connect(SocketAddr::new(ip, port))
            .await
            .map_err(|e| {
                CheckError::new(ErrorKind::Connect, format!("connect to port {port}: {e}"))
            })?;
        trace.timings.connect_ms = Some(ms(start.elapsed()));
        let _ = tcp.set_nodelay(true);
        Ok(tcp)
    }

    /// Connects to a proxy. Timings describe the proxy connection and
    /// `remote_ip` stays unset: through a proxy the target's address is unknown.
    pub async fn connect_proxy(
        &self,
        proxy: &ProxyEndpoint,
        guard: &Guard,
        trace: &mut Trace,
    ) -> Result<TcpStream, CheckError> {
        let r = self
            .connect(&proxy.host, proxy.port, IpVersion::Any, guard, trace)
            .await;
        trace.remote_ip = None;
        r.map_err(|e| CheckError::new(e.kind, format!("proxy {proxy}: {}", e.message)))
    }

    /// A TCP connection to `host:port`, directly or through a CONNECT tunnel.
    pub async fn connect_target(
        &self,
        host: &str,
        port: u16,
        ipv: IpVersion,
        guard: &Guard,
        proxy: Option<&ProxyEndpoint>,
        trace: &mut Trace,
    ) -> Result<TcpStream, CheckError> {
        match proxy {
            None => self.connect(host, port, ipv, guard, trace).await,
            Some(p) => {
                let auth = connect_authority(host, port)?;
                let mut tcp = self.connect_proxy(p, guard, trace).await?;
                tunnel(&mut tcp, &auth, p, trace).await?;
                Ok(tcp)
            }
        }
    }

    /// Runs a TLS handshake over `tcp`. Fills `trace.timings.tls_ms` and
    /// `trace.tls_expires_at` (the leaf certificate's notAfter).
    pub async fn tls_handshake(
        &self,
        tcp: TcpStream,
        host: &str,
        verify: bool,
        trace: &mut Trace,
    ) -> Result<TlsStream<TcpStream>, CheckError> {
        let name = ServerName::try_from(host.to_owned())
            .map_err(|_| CheckError::new(ErrorKind::Tls, "invalid TLS server name"))?;
        let config = if verify {
            self.tls_verify.clone()
        } else {
            self.tls_insecure.clone()
        };
        let start = Instant::now();
        let stream = TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .map_err(tls_error)?;
        trace.timings.tls_ms = Some(ms(start.elapsed()));
        trace.tls_expires_at = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .and_then(|c| cert_not_after(c.as_ref()));
        Ok(stream)
    }

    /// One HTTP/1.1 request on a fresh connection. Fills `trace` as it goes.
    pub async fn http(
        &self,
        req: HttpRequest<'_>,
        trace: &mut Trace,
    ) -> Result<HttpResponse, CheckError> {
        let url = req.url;
        let https = match url.scheme() {
            "https" => true,
            "http" => false,
            other => {
                return Err(CheckError::new(
                    ErrorKind::Other,
                    format!("unsupported URL scheme {other:?}"),
                ))
            }
        };
        let host = host_of(url)?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| CheckError::new(ErrorKind::Other, "URL has no port"))?;

        let mut absolute_form = false;
        let tcp = match req.proxy {
            Some(p) => {
                let auth = connect_authority(&host, port)?;
                let mut tcp = self.connect_proxy(p, req.guard, trace).await?;
                if https {
                    tunnel(&mut tcp, &auth, p, trace).await?;
                } else {
                    absolute_form = true;
                }
                tcp
            }
            None => {
                self.connect(&host, port, req.ip_version, req.guard, trace)
                    .await?
            }
        };

        let target = if absolute_form {
            &url[..url::Position::AfterQuery]
        } else {
            &url[url::Position::BeforePath..url::Position::AfterQuery]
        };
        let mut builder = Request::builder().method(req.method.clone()).uri(target);
        let headers = builder
            .headers_mut()
            .ok_or_else(|| CheckError::new(ErrorKind::Other, "invalid request"))?;
        headers.extend(req.headers.clone());
        if absolute_form {
            if let Some(auth) = req.proxy.and_then(|p| p.authorization.as_deref()) {
                let mut v = HeaderValue::from_str(auth)
                    .map_err(|_| CheckError::new(ErrorKind::Other, "invalid proxy credentials"))?;
                v.set_sensitive(true);
                headers.insert(header::PROXY_AUTHORIZATION, v);
            }
        }
        let host_header = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        headers.insert(
            header::HOST,
            HeaderValue::from_str(&host_header)
                .map_err(|_| CheckError::new(ErrorKind::Other, "invalid host"))?,
        );
        headers
            .entry(header::USER_AGENT)
            .or_insert_with(|| HeaderValue::from_str(&crate::protocol::user_agent()).unwrap());
        headers
            .entry(header::ACCEPT)
            .or_insert(HeaderValue::from_static("*/*"));
        headers
            .entry(header::ACCEPT_ENCODING)
            .or_insert(HeaderValue::from_static("identity"));
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
        let body = req.body.unwrap_or_default();
        if !body.is_empty() || matches!(req.method, Method::POST | Method::PUT | Method::PATCH) {
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        }
        tracing::trace!(
            method = %req.method,
            url = %crate::redact::url_for_log(url.as_str()),
            headers = %crate::redact::headers_for_log(headers),
            "sending request"
        );
        let request = builder
            .body(Full::new(body))
            .map_err(|e| CheckError::new(ErrorKind::Other, format!("invalid request: {e}")))?;

        let is_head = req.method == Method::HEAD;
        if https {
            let tls = self
                .tls_handshake(tcp, &host, req.verify_tls, trace)
                .await?;
            exchange(tls, request, req.max_body, req.keep_body, is_head, trace).await
        } else {
            exchange(tcp, request, req.max_body, req.keep_body, is_head, trace).await
        }
    }
}

/// Validates a host from the platform: an IP literal (brackets optional for
/// IPv6) or a DNS name made of letters, digits, `-`, `_` and `.`. Returns
/// the normalised form (lowercase, no brackets). Anything else, including
/// whitespace or CR/LF that could smuggle bytes into a request line, is
/// refused.
pub fn normalize_host(raw: &str) -> Result<String, CheckError> {
    let invalid = || CheckError::new(ErrorKind::Other, "invalid host");
    let h = raw.trim();
    let h = match h.strip_prefix('[') {
        Some(inner) => inner.strip_suffix(']').ok_or_else(invalid)?,
        None => h,
    };
    if h.is_empty() || h.len() > crate::protocol::limits::MAX_HOST {
        return Err(invalid());
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    match url::Host::parse(h) {
        Ok(url::Host::Domain(d))
            if d.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) =>
        {
            Ok(d)
        }
        Ok(url::Host::Ipv4(ip)) => Ok(ip.to_string()),
        _ => Err(invalid()),
    }
}

/// `host:port` for a CONNECT line, built from a validated host.
fn connect_authority(host: &str, port: u16) -> Result<String, CheckError> {
    let host = normalize_host(host)?;
    Ok(if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

/// Host of a URL without IPv6 brackets.
pub fn host_of(url: &url::Url) -> Result<String, CheckError> {
    match url.host() {
        Some(url::Host::Domain(d)) => Ok(d.to_owned()),
        Some(url::Host::Ipv4(ip)) => Ok(ip.to_string()),
        Some(url::Host::Ipv6(ip)) => Ok(ip.to_string()),
        None => Err(CheckError::new(ErrorKind::Other, "URL has no host")),
    }
}

/// Largest CONNECT response header we accept from a proxy.
const MAX_PROXY_RESPONSE: usize = 16 * 1024;

/// Opens an HTTP CONNECT tunnel to `authority` over a proxy connection. The
/// time it takes is added to `connect_ms`.
async fn tunnel(
    tcp: &mut TcpStream,
    authority: &str,
    proxy: &ProxyEndpoint,
    trace: &mut Trace,
) -> Result<(), CheckError> {
    let conn_err = |m: String| CheckError::new(ErrorKind::Connect, format!("proxy {proxy}: {m}"));
    // Defence in depth: the authority comes from a validated host, but never
    // let anything that could end the request line through.
    if authority.is_empty()
        || authority
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b'@' || b == b'/')
    {
        return Err(CheckError::new(ErrorKind::Other, "invalid host"));
    }
    let start = Instant::now();
    let mut req = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {}\r\n",
        crate::protocol::user_agent()
    );
    if let Some(auth) = &proxy.authorization {
        req.push_str("Proxy-Authorization: ");
        req.push_str(auth);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    tcp.write_all(req.as_bytes())
        .await
        .map_err(|e| conn_err(format!("sending CONNECT: {e}")))?;
    drop(req);

    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_PROXY_RESPONSE {
            return Err(conn_err("response header too large".into()));
        }
        let n = tcp
            .read(&mut chunk)
            .await
            .map_err(|e| conn_err(format!("reading CONNECT response: {e}")))?;
        if n == 0 {
            return Err(conn_err("closed the connection during CONNECT".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    if end != buf.len() {
        return Err(conn_err(
            "sent unexpected data after the CONNECT response".into(),
        ));
    }
    let line = String::from_utf8_lossy(&buf[..buf.iter().position(|&b| b == b'\r').unwrap_or(0)])
        .into_owned();
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| conn_err("invalid CONNECT response".into()))?;
    match status {
        200..=299 => {}
        407 => return Err(conn_err("proxy authentication required (407)".into())),
        s => return Err(conn_err(format!("refused the tunnel (status {s})"))),
    }
    let tunnel_ms = ms(start.elapsed());
    trace.timings.connect_ms = Some(trace.timings.connect_ms.unwrap_or(0) + tunnel_ms);
    Ok(())
}

/// Picks the address to connect to. `any` prefers IPv4 (more widely
/// routable from probe hosts), then IPv6. Order otherwise follows DNS.
pub fn pick_address(ips: &[IpAddr], ipv: IpVersion) -> Option<IpAddr> {
    let v4 = ips.iter().copied().find(IpAddr::is_ipv4);
    let v6 = ips.iter().copied().find(IpAddr::is_ipv6);
    match ipv {
        IpVersion::V4 => v4,
        IpVersion::V6 => v6,
        IpVersion::Any => v4.or(v6),
    }
}

/// Aborts the spawned connection driver when dropped (also on timeout).
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn exchange<S>(
    io: S,
    request: Request<Full<Bytes>>,
    max_body: usize,
    keep_body: bool,
    is_head: bool,
    trace: &mut Trace,
) -> Result<HttpResponse, CheckError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| CheckError::new(ErrorKind::Other, format!("HTTP handshake: {e}")))?;
    let _driver = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let start = Instant::now();
    let response = sender.send_request(request).await.map_err(|e| {
        CheckError::new(ErrorKind::Other, format!("HTTP request: {}", hyper_msg(&e)))
    })?;
    trace.timings.ttfb_ms = Some(ms(start.elapsed()));
    let (parts, mut body) = response.into_parts();
    let mut buf = BytesMut::new();
    let mut read = 0usize;
    if !is_head {
        while read < max_body {
            match body.frame().await {
                None => break,
                Some(Err(e)) => {
                    return Err(CheckError::new(
                        ErrorKind::Other,
                        format!("reading body: {}", hyper_msg(&e)),
                    ))
                }
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        let take = data.len().min(max_body - read);
                        if keep_body {
                            buf.extend_from_slice(&data[..take]);
                        }
                        read += take;
                    }
                }
            }
        }
    }
    Ok(HttpResponse {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body: buf.freeze(),
        body_len: read as u64,
    })
}

fn hyper_msg(e: &hyper::Error) -> String {
    use std::error::Error;
    match e.source() {
        Some(src) => format!("{e}: {src}"),
        None => e.to_string(),
    }
}

fn tls_error(e: std::io::Error) -> CheckError {
    let msg = match e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        Some(rustls::Error::InvalidCertificate(c)) => cert_error_text(c),
        Some(other) => other.to_string(),
        None => e.to_string(),
    };
    CheckError::new(ErrorKind::Tls, format!("TLS handshake failed: {msg}"))
}

fn cert_error_text(c: &rustls::CertificateError) -> String {
    use rustls::CertificateError as C;
    match c {
        C::Expired | C::ExpiredContext { .. } => "certificate expired".into(),
        C::NotValidYet | C::NotValidYetContext { .. } => "certificate is not valid yet".into(),
        C::UnknownIssuer => {
            "certificate issuer is not trusted (self-signed, private CA or missing intermediate)"
                .into()
        }
        C::NotValidForName | C::NotValidForNameContext { .. } => {
            "certificate is not valid for this host name".into()
        }
        C::Revoked => "certificate is revoked".into(),
        C::BadSignature => "certificate has a bad signature".into(),
        other => format!("invalid certificate: {other:?}"),
    }
}

/// notAfter of a DER certificate.
pub fn cert_not_after(der: &[u8]) -> Option<OffsetDateTime> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    OffsetDateTime::from_unix_timestamp(cert.validity().not_after.timestamp()).ok()
}

fn build_resolver() -> Result<TokioResolver, String> {
    let mut builder = match TokioResolver::builder_tokio() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "no usable system DNS configuration; using Cloudflare DNS");
            Resolver::builder_with_config(
                ResolverConfig::udp_and_tcp(&CLOUDFLARE),
                TokioRuntimeProvider::default(),
            )
        }
    };
    let opts = builder.options_mut();
    opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    opts.cache_size = 1024;
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;
    builder.build().map_err(|e| format!("DNS resolver: {e}"))
}

fn tls_configs(ca_file: Option<&Path>) -> Result<(Arc<ClientConfig>, Arc<ClientConfig>), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        let iter = CertificateDer::pem_file_iter(path)
            .map_err(|e| format!("ca_file {}: {e}", path.display()))?;
        let mut added = 0;
        for cert in iter {
            let cert = cert.map_err(|e| format!("ca_file {}: {e}", path.display()))?;
            roots
                .add(cert)
                .map_err(|e| format!("ca_file {}: {e}", path.display()))?;
            added += 1;
        }
        if added == 0 {
            return Err(format!("ca_file {}: no certificates found", path.display()));
        }
    }

    let mut verify = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Every check measures a full handshake and sees the current certificate.
    verify.resumption = Resumption::disabled();

    let mut insecure = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
        .with_no_client_auth();
    insecure.resumption = Resumption::disabled();

    Ok((Arc::new(verify), Arc::new(insecure)))
}

/// Used only for checks with `verify_tls = false`: accepts any certificate,
/// but still checks the handshake signatures.
#[derive(Debug)]
struct AcceptAnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_by_family() {
        let ips: Vec<IpAddr> = vec![
            "2001:db8::1".parse().unwrap(),
            "203.0.113.7".parse().unwrap(),
        ];
        assert_eq!(pick_address(&ips, IpVersion::Any), Some(ips[1]));
        assert_eq!(pick_address(&ips, IpVersion::V4), Some(ips[1]));
        assert_eq!(pick_address(&ips, IpVersion::V6), Some(ips[0]));
        assert_eq!(pick_address(&ips[..1], IpVersion::V4), None);
        assert_eq!(pick_address(&ips[..1], IpVersion::Any), Some(ips[0]));
    }

    #[tokio::test]
    async fn ip_literal_skips_dns_and_checks_family() {
        let net = Net::new(None).unwrap();
        assert_eq!(
            net.resolve("127.0.0.1", IpVersion::Any).await.unwrap(),
            ("127.0.0.1".parse().unwrap(), 0)
        );
        let e = net.resolve("::1", IpVersion::V4).await.unwrap_err();
        assert_eq!(e.kind, ErrorKind::Dns);
    }

    #[tokio::test]
    async fn blocks_private_without_connecting() {
        let net = Net::new(None).unwrap();
        let mut t = Trace::default();
        let e = net
            .connect(
                "169.254.169.254",
                80,
                IpVersion::Any,
                &Guard::new(false),
                &mut t,
            )
            .await
            .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Blocked);
        assert!(t.remote_ip.is_none());
        assert!(t.timings.connect_ms.is_none());
    }
}
