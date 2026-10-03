//! Shared helpers: local target servers and a mock bynh platform.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::Instant;

use bynh_status_agent::agent::{Agent, Tunables};
use bynh_status_agent::config::Config;

pub const TOKEN: &str = "bynh_agt_01HTEST_abcdefghijklmnopqrstuvwxyz0123456789ABCD";

async fn serve(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[derive(serde::Deserialize)]
struct To {
    to: String,
}

/// A plain-HTTP target with routes for every probe scenario.
pub async fn spawn_target() -> SocketAddr {
    let app =
        Router::new()
            .route("/ok", get(|| async { "service is OK" }))
            .route(
                "/fail",
                get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "down") }),
            )
            .route("/redirect", get(|| async { Redirect::temporary("/ok") }))
            .route(
                "/found",
                get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/ok")]) }),
            )
            .route(
                "/loop",
                get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/loop")]) }),
            )
            .route(
                "/to-private",
                get(|| async { (StatusCode::FOUND, [(header::LOCATION, "http://10.0.0.1/")]) }),
            )
            .route(
                "/to",
                get(|Query(q): Query<To>| async move {
                    (StatusCode::FOUND, [(header::LOCATION, q.to)])
                }),
            )
            .route(
                "/big",
                get(|| async {
                    let mut body = vec![b'a'; 1 << 20];
                    body.extend_from_slice(b"needle");
                    body
                }),
            )
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    "late"
                }),
            )
            .route(
                "/echo-auth",
                get(|h: HeaderMap| async move {
                    if h.contains_key(header::AUTHORIZATION) {
                        "auth=present"
                    } else {
                        "auth=none"
                    }
                }),
            )
            .route(
                "/echo",
                any(|m: Method, h: HeaderMap, body: String| async move {
                    let probe = h
                        .get("x-probe")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-")
                        .to_owned();
                    format!("method={m} body={body} x-probe={probe}")
                }),
            )
            .route("/post-303", post(|| async { Redirect::to("/echo") }));
    serve(app).await
}

/// A minimal HTTPS server with a self-signed certificate for `localhost`
/// valid until `not_after`.
pub async fn spawn_tls(not_after: OffsetDateTime) -> SocketAddr {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params.not_before = not_after - time::Duration::days(365);
    params.not_after = not_after;
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecure",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

// ---------------------------------------------------------------------------
// Mock platform

#[derive(Debug, Clone)]
pub struct Call {
    pub at: Instant,
    pub headers: HeaderMap,
    pub status: u16,
}

#[derive(Debug, Clone)]
pub struct ResultsCall {
    pub call: Call,
    pub results: Vec<Value>,
}

pub struct MockState {
    pub hello_status: u16,
    pub hello_upgrade_min: String,
    pub poll_interval: u64,
    pub report_interval: u64,
    pub max_batch: usize,
    pub assignments_status: u16,
    pub config_version: String,
    pub checks: Value,
    /// Scripted results responses: (status, Retry-After). Empty → 202.
    pub results_script: VecDeque<(u16, Option<String>)>,

    pub hello_calls: Vec<Call>,
    pub assignment_calls: Vec<Call>,
    pub results_calls: Vec<ResultsCall>,
}

impl Default for MockState {
    fn default() -> Self {
        Self {
            hello_status: 200,
            hello_upgrade_min: "9.0.0".into(),
            poll_interval: 1,
            report_interval: 1,
            max_batch: 500,
            assignments_status: 200,
            config_version: "c_1".into(),
            checks: json!([]),
            results_script: VecDeque::new(),
            hello_calls: Vec::new(),
            assignment_calls: Vec::new(),
            results_calls: Vec::new(),
        }
    }
}

pub type Mock = Arc<Mutex<MockState>>;

fn auth_ok(h: &HeaderMap) -> bool {
    h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"))
}

async fn hello(State(m): State<Mock>, h: HeaderMap, body: Bytes) -> Response {
    let mut s = m.lock().unwrap();
    let v: Value = serde_json::from_slice(&body).expect("hello body is JSON");
    assert!(v["version"].is_string() && v["os"].is_string() && v["arch"].is_string());
    assert!(v["started_at"].as_str().unwrap().ends_with('Z'));
    let status = if auth_ok(&h) { s.hello_status } else { 401 };
    s.hello_calls.push(Call {
        at: Instant::now(),
        headers: h,
        status,
    });
    match status {
        200 => Json(json!({
            "agent": { "id": "agt_test", "name": "Test probe", "kind": "own", "region": null, "location": null },
            "poll_interval_seconds": s.poll_interval,
            "report_interval_seconds": s.report_interval,
            "max_batch": s.max_batch,
            "minimum_version": "1.0.0",
            "latest_version": "1.0.0"
        }))
        .into_response(),
        426 => (
            StatusCode::UPGRADE_REQUIRED,
            Json(json!({ "message": "please upgrade", "minimum_version": s.hello_upgrade_min })),
        )
            .into_response(),
        other => StatusCode::from_u16(other).unwrap().into_response(),
    }
}

async fn assignments(State(m): State<Mock>, h: HeaderMap) -> Response {
    let mut s = m.lock().unwrap();
    let etag = format!("\"{}\"", s.config_version);
    let inm = h
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let status = if s.assignments_status != 200 {
        s.assignments_status
    } else if inm.as_deref() == Some(etag.as_str()) {
        304
    } else {
        200
    };
    s.assignment_calls.push(Call {
        at: Instant::now(),
        headers: h,
        status,
    });
    match status {
        200 => (
            [(header::ETAG, etag)],
            Json(json!({ "config_version": s.config_version, "checks": s.checks })),
        )
            .into_response(),
        other => StatusCode::from_u16(other).unwrap().into_response(),
    }
}

async fn results(State(m): State<Mock>, h: HeaderMap, body: Bytes) -> Response {
    let mut s = m.lock().unwrap();
    let raw = if h.get(header::CONTENT_ENCODING).map(|v| v.as_bytes()) == Some(b"gzip") {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&body[..])
            .read_to_end(&mut out)
            .unwrap();
        out
    } else {
        body.to_vec()
    };
    let v: Value = serde_json::from_slice(&raw).expect("results body is JSON");
    let list = v["results"].as_array().cloned().unwrap_or_default();
    let (status, retry_after) = if !auth_ok(&h) {
        (401, None)
    } else {
        s.results_script.pop_front().unwrap_or((202, None))
    };
    let n = list.len();
    s.results_calls.push(ResultsCall {
        call: Call {
            at: Instant::now(),
            headers: h,
            status,
        },
        results: list,
    });
    let mut resp = if status == 202 {
        (
            StatusCode::ACCEPTED,
            Json(json!({ "accepted": n, "rejected": [] })),
        )
            .into_response()
    } else {
        StatusCode::from_u16(status).unwrap().into_response()
    };
    if let Some(ra) = retry_after {
        resp.headers_mut()
            .insert(header::RETRY_AFTER, ra.parse().unwrap());
    }
    resp
}

pub async fn spawn_platform() -> (SocketAddr, Mock) {
    let mock: Mock = Arc::new(Mutex::new(MockState::default()));
    let app = Router::new()
        .route("/api/v1/agent/hello", post(hello))
        .route("/api/v1/agent/assignments", get(assignments))
        .route("/api/v1/agent/results", post(results))
        .with_state(mock.clone());
    (serve(app).await, mock)
}

/// Polls `cond` until it holds or `timeout` passes.
pub async fn wait_for(mock: &Mock, timeout: Duration, cond: impl Fn(&MockState) -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if cond(&mock.lock().unwrap()) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub fn fast_tunables() -> Tunables {
    Tunables {
        auth_retry: Duration::from_millis(400),
        upgrade_retry: Duration::from_millis(400),
        backoff_base: Duration::from_millis(50),
        backoff_cap: Duration::from_millis(200),
        flush_deadline: Duration::from_secs(3),
        request_timeout: Duration::from_secs(5),
        ..Tunables::default()
    }
}

pub fn agent_for(platform: SocketAddr) -> Agent {
    let config = Config {
        token: Some(TOKEN.into()),
        api_url: format!("http://{platform}"),
        allow_private: true,
        send_hostname: false,
        ..Config::default()
    };
    Agent::new(config, fast_tunables()).unwrap()
}

/// A check JSON object as the platform would send it.
pub fn http_check(id: &str, url: &str) -> Value {
    json!({
        "id": id, "type": "http", "url": url, "method": "GET", "headers": {},
        "body": null, "auth": null, "timeout_ms": 2000, "interval_seconds": 1,
        "expected_statuses": ["2xx"], "keyword": null, "keyword_absent": false,
        "follow_redirects": true, "max_redirects": 5, "verify_tls": true, "ip_version": "any"
    })
}

pub fn ids(results: &[Value]) -> Vec<String> {
    results
        .iter()
        .map(|r| r["check_id"].as_str().unwrap().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// A tiny forward proxy: CONNECT tunnels and absolute-form HTTP requests.

pub type ProxyLog = Arc<Mutex<Vec<String>>>;

/// Starts a proxy. With `require_auth`, requests must carry
/// `Proxy-Authorization: <value>` or get a 407. Logs each request line.
pub async fn spawn_proxy(require_auth: Option<&'static str>) -> (SocketAddr, ProxyLog) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log: ProxyLog = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let log = log2.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let end = loop {
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                    match client.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                let line = head.lines().next().unwrap_or("").to_owned();
                log.lock().unwrap().push(line.clone());
                if let Some(expected) = require_auth {
                    let ok = head.lines().any(|l| {
                        l.to_ascii_lowercase().starts_with("proxy-authorization:")
                            && l.split_once(':').unwrap().1.trim() == expected
                    });
                    if !ok {
                        let _ = client
                            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
                            .await;
                        return;
                    }
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let target = parts.next().unwrap_or("").to_owned();
                if method == "CONNECT" {
                    let Ok(mut upstream) =
                        tokio::net::TcpStream::connect(resolve_local(&target)).await
                    else {
                        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                        return;
                    };
                    let _ = client
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                } else {
                    let url = url::Url::parse(&target).unwrap();
                    let hostport = format!(
                        "{}:{}",
                        url.host_str().unwrap(),
                        url.port_or_known_default().unwrap()
                    );
                    let Ok(mut upstream) =
                        tokio::net::TcpStream::connect(resolve_local(&hostport)).await
                    else {
                        return;
                    };
                    let _ = upstream.write_all(&buf).await;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
            });
        }
    });
    (addr, log)
}

/// The test proxy maps `localhost` to 127.0.0.1.
fn resolve_local(hostport: &str) -> String {
    hostport.replace("localhost", "127.0.0.1")
}
