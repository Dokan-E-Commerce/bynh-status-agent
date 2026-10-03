//! Check details (agent 1.1.0) against local servers and the mock platform.

mod common;

use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bynh_status_agent::details::{self, MAX_RESULT_BYTES, REDACTED, SAMPLE_MAX};
use bynh_status_agent::net::Net;
use bynh_status_agent::netguard::Guard;
use bynh_status_agent::probe::Prober;
use bynh_status_agent::protocol::{Check, CheckResult, CheckType, ErrorKind};
use serde_json::{json, Value};
use time::OffsetDateTime;

use common::{spawn_target, spawn_tls, PAGE};

fn prober() -> Prober {
    Prober::new(Arc::new(Net::new(None).unwrap()), Guard::new(true), true)
}

fn http(url: String) -> Check {
    let mut c = Check::new("mon_test", CheckType::Http);
    c.url = Some(url);
    c.timeout_ms = 3000;
    c
}

fn header<'a>(r: &'a CheckResult, name: &str) -> Option<&'a str> {
    r.details
        .as_ref()
        .unwrap()
        .response_headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn html_page_details() {
    let t = spawn_target().await;
    let r = prober().run(&http(format!("http://{t}/page"))).await;
    assert!(r.ok, "{r:?}");
    let d = r.details.as_ref().unwrap();
    assert_eq!(d.http_version, Some("HTTP/1.1"));
    assert_eq!(d.ip_family, Some("4"));
    let req = d.request.as_ref().unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(req.url, format!("http://{t}/page"));
    assert_eq!(d.status_text.as_deref(), Some("OK"));
    assert_eq!(header(&r, "content-type"), Some("text/html; charset=utf-8"));
    assert_eq!(header(&r, "server"), Some("test-server"));
    assert_eq!(header(&r, "x-request-id"), Some("req-1"));
    assert_eq!(header(&r, "set-cookie"), Some(REDACTED));
    assert_eq!(header(&r, "x-api-key"), Some(REDACTED));
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("hunter"), "secret header value sent: {json}");

    let body = d.body.as_ref().unwrap();
    assert_eq!(body.sample.as_deref(), Some(PAGE));
    assert!(!body.sample_base64 && !body.truncated);
    assert_eq!(body.size, Some(PAGE.len() as u64));
    assert_eq!(body.size, r.response_bytes);
    assert_eq!(
        body.sha256.as_deref(),
        Some(details::sha256_hex(PAGE.as_bytes()).as_str())
    );
    assert_eq!(
        body.content_type.as_deref(),
        Some("text/html; charset=utf-8")
    );
    assert!(d.redirects.is_empty() && d.tls.is_none());
    let t = d.timings.as_ref().unwrap();
    assert!(t.connect_ms.is_some() && t.ttfb_ms.is_some());
    assert!(t.download_ms.is_some() && t.total_ms.is_some());
    assert_eq!(t.tls_ms, None);
    println!("typical HTML result: {} bytes of JSON", json.len());
}

#[tokio::test]
async fn binary_body_is_base64() {
    let t = spawn_target().await;
    let r = prober().run(&http(format!("http://{t}/binary"))).await;
    let body = r.details.unwrap().body.unwrap();
    assert!(body.sample_base64);
    let raw = base64::engine::general_purpose::STANDARD
        .decode(body.sample.unwrap())
        .unwrap();
    assert_eq!(raw, (0..=255u8).collect::<Vec<u8>>());
    assert_eq!(body.content_type.as_deref(), Some("image/png"));
}

#[tokio::test]
async fn capture_body_false_sends_no_content() {
    let t = spawn_target().await;
    let mut c = http(format!("http://{t}/page"));
    c.capture_body = false;
    let r = prober().run(&c).await;
    let body = r.details.as_ref().unwrap().body.clone().unwrap();
    assert_eq!(body.sample, None);
    assert!(!body.sample_base64);
    assert_eq!(body.size, Some(PAGE.len() as u64));
    assert!(body.sha256.is_some() && body.content_type.is_some());
    assert!(!serde_json::to_string(&r).unwrap().contains("<title>"));
    // Keyword checks still work on the full body without sending it.
    c.kind = CheckType::Keyword;
    c.keyword = Some("status: OK".into());
    let r = prober().run(&c).await;
    assert!(r.ok);
    assert_eq!(r.details.unwrap().body.unwrap().sample, None);
}

#[tokio::test]
async fn big_body_stays_within_budget() {
    let t = spawn_target().await;
    let r = prober().run(&http(format!("http://{t}/big"))).await;
    assert!(r.ok);
    let body = r.details.as_ref().unwrap().body.clone().unwrap();
    assert!(body.truncated);
    assert_eq!(body.size, Some(1 << 20));
    assert!(body.sample.unwrap().len() <= SAMPLE_MAX);
    assert!(details::json_len(&r) <= MAX_RESULT_BYTES);
}

#[tokio::test]
async fn redirect_hops_are_captured() {
    let t = spawn_target().await;
    let r = prober()
        .run(&http(format!("http://{t}/to?to=/redirect")))
        .await;
    assert!(r.ok, "{r:?}");
    let d = r.details.as_ref().unwrap();
    assert_eq!(
        d.request.as_ref().unwrap().url,
        format!("http://{t}/to?to=/redirect")
    );
    assert_eq!(d.redirects.len(), 2);
    assert_eq!(d.redirects[0].url, format!("http://{t}/redirect"));
    assert_eq!(d.redirects[0].status, 302);
    assert_eq!(d.redirects[0].remote_ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(d.redirects[1].url, format!("http://{t}/ok"), "final URL");
    assert_eq!(d.redirects[1].status, 307);
    assert_eq!(
        d.body.as_ref().unwrap().sample.as_deref(),
        Some("service is OK")
    );

    // report_ip = false leaves the hop addresses out entirely.
    let p = Prober::new(Arc::new(Net::new(None).unwrap()), Guard::new(true), false);
    let r = p.run(&http(format!("http://{t}/redirect"))).await;
    let v = serde_json::to_value(&r).unwrap();
    let hop = &v["details"]["redirects"][0];
    assert_eq!(hop["status"], 307);
    assert!(hop.get("remote_ip").is_none(), "{hop}");
    assert!(v["remote_ip"].is_null());

    // A redirect that is not followed is the last response, not a hop.
    let mut c = http(format!("http://{t}/found"));
    c.max_redirects = 0;
    let r = prober().run(&c).await;
    assert_eq!(r.error.as_ref().unwrap().kind, ErrorKind::Redirects);
    let d = r.details.unwrap();
    assert!(d.redirects.is_empty());
    assert_eq!(d.status_text.as_deref(), Some("Found"));
    assert!(d
        .response_headers
        .iter()
        .any(|(n, v)| n == "location" && v == "/ok"));
}

#[tokio::test]
async fn credentials_never_appear_in_details() {
    let t = spawn_target().await;
    // User info in the monitor URL becomes basic auth; user info in a
    // Location is discarded. Neither, nor monitor headers, reach the details.
    let mut c = http(format!(
        "http://monitor:pw-one@{t}/to?to=http://user:pw-two@{t}/echo-auth"
    ));
    c.headers.insert("X-Api-Key".into(), "pw-three".into());
    let r = prober().run(&c).await;
    assert!(r.ok, "{r:?}");
    let json = serde_json::to_string(&r).unwrap();
    assert!(
        !json.contains("pw-one") && !json.contains("pw-three"),
        "{json}"
    );
    let d = r.details.unwrap();
    assert_eq!(
        d.request.unwrap().url,
        format!("http://{t}/to?to=http://user:pw-two@{t}/echo-auth"),
        "the configured URL, minus its own user info"
    );
    assert_eq!(d.redirects[0].url, format!("http://{t}/echo-auth"));
}

#[tokio::test]
async fn at_most_ten_hops_are_reported() {
    let t = spawn_target().await;
    // 12 redirects in a chain: /to?to=/to?to=…/ok
    let mut target = "/ok".to_owned();
    for _ in 0..12 {
        target = format!("/to?to={}", urlencode(&target));
    }
    let mut c = http(format!("http://{t}{target}"));
    c.max_redirects = 20;
    let r = prober().run(&c).await;
    assert!(r.ok, "{r:?}");
    let hops = r.details.unwrap().redirects;
    assert_eq!(hops.len(), details::MAX_REDIRECTS);
    assert_eq!(hops.last().unwrap().url, format!("http://{t}/ok"));
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[tokio::test]
async fn status_and_keyword_failures_include_headers_and_body() {
    let t = spawn_target().await;
    let r = prober().run(&http(format!("http://{t}/fail"))).await;
    assert_eq!(r.error.as_ref().unwrap().kind, ErrorKind::Status);
    let d = r.details.as_ref().unwrap();
    assert_eq!(d.status_text.as_deref(), Some("Service Unavailable"));
    assert!(header(&r, "content-type").is_some());
    assert_eq!(d.body.as_ref().unwrap().sample.as_deref(), Some("down"));

    let mut c = http(format!("http://{t}/page"));
    c.kind = CheckType::Keyword;
    c.keyword = Some("maintenance".into());
    let r = prober().run(&c).await;
    assert_eq!(r.error.as_ref().unwrap().kind, ErrorKind::Keyword);
    assert_eq!(header(&r, "server"), Some("test-server"));
    assert_eq!(
        r.details.unwrap().body.unwrap().sample.as_deref(),
        Some(PAGE)
    );
}

#[tokio::test]
async fn timeout_mid_body_keeps_headers_and_partial_body() {
    let s = common::spawn_raw(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\nX-Probe: slow\r\n\r\n",
        b"partial",
        Duration::from_secs(5),
    )
    .await;
    let mut c = http(format!("http://{s}/"));
    c.timeout_ms = 500;
    let r = prober().run(&c).await;
    assert_eq!(r.error.as_ref().unwrap().kind, ErrorKind::Timeout);
    assert_eq!(header(&r, "x-probe"), Some("slow"));
    let d = r.details.unwrap();
    let body = d.body.unwrap();
    assert_eq!(body.sample.as_deref(), Some("partial"));
    assert_eq!(body.size, Some(7));
    let t = d.timings.unwrap();
    assert!(t.ttfb_ms.is_some());
    assert_eq!(t.download_ms, None, "cut off by the timeout");
    assert_eq!(t.total_ms, None);
}

#[tokio::test]
async fn connect_failure_has_no_response_details() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut c = http(format!("http://{closed}/"));
    c.timeout_ms = 10_000;
    let r = prober().run(&c).await;
    assert_eq!(r.error.as_ref().unwrap().kind, ErrorKind::Connect);
    let d = r.details.unwrap();
    assert!(d.request.is_some(), "the request is still described");
    assert!(d.body.is_none() && d.status_text.is_none() && d.http_version.is_none());
    assert!(d.response_headers.is_empty());
    let t = d.timings.unwrap();
    assert_eq!(t.dns_ms, Some(0));
    assert_eq!(t.connect_ms, None);
    assert!(t.total_ms.is_some());
}

#[tokio::test]
async fn blocked_target_reports_no_address() {
    let p = Prober::new(Arc::new(Net::new(None).unwrap()), Guard::new(false), true);
    let r = p.run(&http("http://127.0.0.1:9/".into())).await;
    assert_eq!(r.error.as_ref().unwrap().kind, ErrorKind::Blocked);
    let d = r.details.unwrap();
    assert_eq!(d.ip_family, None);
}

#[tokio::test]
async fn tls_details_from_a_trusted_chain() {
    let (s, ca_pem) = common::spawn_tls_ca().await;
    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(ca_pem.as_bytes()).unwrap();
    let p = Prober::new(
        Arc::new(Net::new(Some(ca.path())).unwrap()),
        Guard::new(true),
        true,
    );
    let r = p
        .run(&http(format!("https://localhost:{}/", s.port())))
        .await;
    assert!(r.ok, "{r:?}");
    let tls = r.details.as_ref().unwrap().tls.clone().unwrap();
    assert_eq!(tls.protocol.as_deref(), Some("TLSv1.3"));
    assert!(
        tls.cipher.as_deref().unwrap().starts_with("TLS13_"),
        "{tls:?}"
    );
    assert_eq!(tls.subject.as_deref(), Some("CN=localhost"));
    assert_eq!(tls.issuer.as_deref(), Some("CN=bynh test CA"));
    assert_eq!(tls.sans, ["localhost", "127.0.0.1"]);
    assert_eq!(tls.chain_length, 2);
    assert!(tls.verified, "{tls:?}");
    assert_eq!(tls.verify_error, None);
    assert_eq!(tls.fingerprint_sha256.as_ref().unwrap().len(), 64);
    assert!(tls.not_before.is_some());
    assert_eq!(tls.not_after, r.tls_expires_at);
    assert!(r.details.unwrap().timings.unwrap().tls_ms.is_some());
}

#[tokio::test]
async fn tls_details_when_verification_fails() {
    let s = spawn_tls(OffsetDateTime::now_utc() + time::Duration::days(30)).await;
    let url = format!("https://localhost:{}/", s.port());

    // verify_tls = false: the check passes, the details say it didn't verify.
    let mut c = http(url.clone());
    c.verify_tls = false;
    let r = prober().run(&c).await;
    assert!(r.ok, "{r:?}");
    let tls = r.details.unwrap().tls.unwrap();
    assert!(!tls.verified);
    assert!(tls.verify_error.unwrap().contains("not trusted"));
    assert_eq!(tls.protocol.as_deref(), Some("TLSv1.3"));
    assert_eq!(tls.chain_length, 1);

    // verify_tls = true: the handshake fails, the certificate is still described.
    let r = prober().run(&http(url)).await;
    assert_eq!(r.error.as_ref().unwrap().kind, ErrorKind::Tls);
    let d = r.details.unwrap();
    let tls = d.tls.unwrap();
    assert!(!tls.verified && tls.verify_error.is_some());
    assert_eq!(tls.protocol, None);
    assert_eq!(tls.cipher, None);
    assert_eq!(tls.sans, ["localhost"]);
    assert!(tls.fingerprint_sha256.is_some() && tls.not_after.is_some());
    assert!(d.body.is_none() && d.response_headers.is_empty());
    assert!(
        r.tls_expires_at.is_none(),
        "v1 field unchanged for http checks"
    );

    // tls checks describe the certificate too.
    let mut c = Check::new("mon_tls", CheckType::Tls);
    c.host = Some("localhost".into());
    c.port = Some(s.port());
    c.verify_tls = false;
    let r = prober().run(&c).await;
    assert!(r.ok);
    let d = r.details.unwrap();
    assert!(d.request.is_none() && d.body.is_none());
    assert!(d.tls.is_some());
    let t = d.timings.unwrap();
    assert!(t.tls_ms.is_some() && t.total_ms.is_some() && t.download_ms.is_none());
}

#[tokio::test]
async fn tcp_check_details() {
    let t = spawn_target().await;
    let mut c = Check::new("mon_tcp", CheckType::Tcp);
    c.host = Some("127.0.0.1".into());
    c.port = Some(t.port());
    let r = prober().run(&c).await;
    assert!(r.ok);
    let d = r.details.unwrap();
    assert_eq!(d.ip_family, Some("4"));
    assert!(d.request.is_none() && d.tls.is_none() && d.body.is_none());
    assert!(d.timings.unwrap().total_ms.is_some());
}

/// Every key the agent can send in `details`, with its JSON type.
fn assert_details_shape(d: &Value) {
    let obj = d.as_object().expect("details is an object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "body",
            "http_version",
            "ip_family",
            "redirects",
            "request",
            "response_headers",
            "status_text",
            "timings",
            "tls"
        ]
    );
    for pair in d["response_headers"].as_array().unwrap() {
        let pair = pair.as_array().unwrap();
        assert_eq!(pair.len(), 2);
        assert!(pair[0].is_string() && pair[1].is_string());
    }
    let body = d["body"].as_object().unwrap();
    let mut body_keys: Vec<&str> = body
        .keys()
        .map(String::as_str)
        .filter(|k| *k != "sample_omitted")
        .collect();
    body_keys.sort_unstable();
    assert_eq!(
        body_keys,
        [
            "content_type",
            "sample",
            "sample_base64",
            "sha256",
            "size",
            "truncated"
        ]
    );
    let timings = d["timings"].as_object().unwrap();
    let mut t_keys: Vec<&str> = timings.keys().map(String::as_str).collect();
    t_keys.sort_unstable();
    assert_eq!(
        t_keys,
        [
            "connect_ms",
            "dns_ms",
            "download_ms",
            "tls_ms",
            "total_ms",
            "ttfb_ms"
        ]
    );
    assert!(d["request"]["method"].is_string() && d["request"]["url"].is_string());
}

#[tokio::test]
async fn platform_receives_details() {
    let target = spawn_target().await;
    let (platform, mock) = common::spawn_platform().await;
    {
        let mut s = mock.lock().unwrap();
        let mut page = common::http_check("mon_page", &format!("http://{target}/page"));
        page["capture_body"] = json!(true);
        let mut quiet = common::http_check("mon_quiet", &format!("http://{target}/page"));
        quiet["capture_body"] = json!(false);
        s.checks = json!([page, quiet]);
    }
    let agent = common::agent_for(platform);
    let shutdown = tokio_util::sync::CancellationToken::new();
    let handle = tokio::spawn(agent.run(shutdown.clone()));
    let got = common::wait_for(&mock, Duration::from_secs(10), |s| {
        let all: Vec<_> = s.results_calls.iter().flat_map(|c| &c.results).collect();
        all.iter().any(|r| r["check_id"] == "mon_page")
            && all.iter().any(|r| r["check_id"] == "mon_quiet")
            && all.iter().any(|r| {
                r["check_id"] == "mon_page" && r["details"]["body"]["sample_omitted"] == "unchanged"
            })
    })
    .await;
    shutdown.cancel();
    let _ = handle.await;
    assert!(got, "no results with details arrived");

    let s = mock.lock().unwrap();
    let all: Vec<&Value> = s.results_calls.iter().flat_map(|c| &c.results).collect();
    let page = all.iter().find(|r| r["check_id"] == "mon_page").unwrap();
    assert_eq!(page["ok"], true);
    let d = &page["details"];
    assert_details_shape(d);
    assert_eq!(d["http_version"], "HTTP/1.1");
    assert_eq!(d["status_text"], "OK");
    assert_eq!(d["body"]["sample"], PAGE);
    assert_eq!(d["body"]["sample_base64"], false);
    assert!(d["tls"].is_null());
    assert_eq!(d["redirects"], json!([]));
    let headers = d["response_headers"].as_array().unwrap();
    assert!(headers.contains(&json!(["set-cookie", "[redacted]"])));
    assert!(!page.to_string().contains("hunter"));

    // Later results of the unchanged page leave the sample out.
    let later = all
        .iter()
        .find(|r| r["check_id"] == "mon_page" && r["details"]["body"]["sample"].is_null())
        .unwrap();
    assert_details_shape(&later["details"]);
    assert_eq!(later["details"]["body"]["sample_omitted"], "unchanged");
    assert_eq!(later["details"]["body"]["sha256"], d["body"]["sha256"]);

    let quiet = all.iter().find(|r| r["check_id"] == "mon_quiet").unwrap();
    assert_details_shape(&quiet["details"]);
    assert!(quiet["details"]["body"]["sample"].is_null());
    assert_eq!(quiet["details"]["body"]["size"], PAGE.len());
}

fn sample_state(r: &CheckResult) -> (bool, Option<&'static str>) {
    let b = r.details.as_ref().unwrap().body.as_ref().unwrap();
    (b.sample.is_some(), b.sample_omitted)
}

const SENT: (bool, Option<&str>) = (true, None);
const OMITTED: (bool, Option<&str>) = (false, Some("unchanged"));

#[tokio::test]
async fn samples_first_then_omits_unchanged() {
    let t = spawn_target().await;
    let p = prober();
    let c = http(format!("http://{t}/page"));
    let first = p.run(&c).await;
    assert_eq!(sample_state(&first), SENT, "first result after start");
    let second = p.run(&c).await;
    assert!(second.ok);
    assert_eq!(sample_state(&second), OMITTED);
    let d = second.details.as_ref().unwrap();
    let b = d.body.as_ref().unwrap();
    // Everything but the sample is still there.
    assert_eq!(b.size, Some(PAGE.len() as u64));
    assert_eq!(
        b.sha256,
        first
            .details
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
            .sha256
    );
    assert!(b.content_type.is_some() && !b.sample_base64 && !b.truncated);
    assert!(!d.response_headers.is_empty() && d.timings.is_some());
    let v = serde_json::to_value(&second).unwrap();
    assert_eq!(v["details"]["body"]["sample_omitted"], "unchanged");
    assert!(v["details"]["body"]["sample"].is_null());
    // Present only when omitted.
    let v = serde_json::to_value(&first).unwrap();
    assert!(v["details"]["body"].get("sample_omitted").is_none());
    // Per check id: another check gets its own first sample.
    let mut other = c.clone();
    other.id = "mon_other".into();
    assert_eq!(sample_state(&p.run(&other).await), SENT);
}

#[tokio::test]
async fn samples_when_the_body_changes() {
    let t = spawn_target().await;
    let p = prober();
    let mut c = http(format!("http://{t}/page"));
    assert_eq!(sample_state(&p.run(&c).await), SENT);
    c.url = Some(format!("http://{t}/ok")); // same check, different body
    assert_eq!(sample_state(&p.run(&c).await), SENT);
    assert_eq!(sample_state(&p.run(&c).await), OMITTED);
    c.url = Some(format!("http://{t}/page")); // back: differs from the last sent
    assert_eq!(sample_state(&p.run(&c).await), SENT);
}

#[tokio::test]
async fn samples_on_every_failure() {
    let t = spawn_target().await;
    let p = prober();
    let c = http(format!("http://{t}/fail"));
    for _ in 0..3 {
        let r = p.run(&c).await;
        assert!(!r.ok);
        assert_eq!(sample_state(&r), SENT);
    }
    // A keyword failure on an otherwise unchanged body samples too.
    let mut k = http(format!("http://{t}/page"));
    k.kind = CheckType::Keyword;
    k.keyword = Some("status: OK".into());
    assert_eq!(sample_state(&p.run(&k).await), SENT);
    assert_eq!(sample_state(&p.run(&k).await), OMITTED);
    k.keyword = Some("maintenance".into());
    let r = p.run(&k).await;
    assert_eq!(r.error.as_ref().unwrap().kind, ErrorKind::Keyword);
    assert_eq!(sample_state(&r), SENT);
}

#[tokio::test]
async fn samples_again_after_the_refresh_interval() {
    let t = spawn_target().await;
    let p = prober().with_sample_refresh(Duration::from_millis(300));
    let c = http(format!("http://{t}/page"));
    assert_eq!(sample_state(&p.run(&c).await), SENT);
    assert_eq!(sample_state(&p.run(&c).await), OMITTED);
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(sample_state(&p.run(&c).await), SENT, "refreshed");
    assert_eq!(sample_state(&p.run(&c).await), OMITTED);
    assert_eq!(
        bynh_status_agent::probe::SAMPLE_REFRESH,
        Duration::from_secs(3600)
    );
}

#[tokio::test]
async fn unassigning_a_check_forgets_its_sample() {
    let t = spawn_target().await;
    let p = prober();
    let c = http(format!("http://{t}/page"));
    assert_eq!(sample_state(&p.run(&c).await), SENT);
    assert_eq!(sample_state(&p.run(&c).await), OMITTED);
    p.forget("mon_other");
    assert_eq!(
        sample_state(&p.run(&c).await),
        OMITTED,
        "other ids untouched"
    );
    p.forget(&c.id);
    assert_eq!(sample_state(&p.run(&c).await), SENT);
}

#[tokio::test]
async fn capture_body_false_never_marks_omitted() {
    let t = spawn_target().await;
    let p = prober();
    let mut c = http(format!("http://{t}/page"));
    c.capture_body = false;
    for _ in 0..2 {
        let r = p.run(&c).await;
        assert_eq!(sample_state(&r), (false, None));
        let v = serde_json::to_value(&r).unwrap();
        assert!(v["details"]["body"].get("sample_omitted").is_none());
    }
    // Turning capture back on starts with a sample (none was sent before).
    c.capture_body = true;
    assert_eq!(sample_state(&p.run(&c).await), SENT);
}
