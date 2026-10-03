//! Probes against local target servers.

mod common;

use std::net::IpAddr;
use std::sync::Arc;

use bynh_status_agent::net::Net;
use bynh_status_agent::netguard::Guard;
use bynh_status_agent::probe::Prober;
use bynh_status_agent::protocol::{Auth, Check, CheckType, ErrorKind};
use time::OffsetDateTime;

use common::{spawn_target, spawn_tls};

const LOOPBACK: &str = "127.0.0.1";

fn prober(allow_private: bool) -> Prober {
    Prober::new(
        Arc::new(Net::new(None).unwrap()),
        Guard::new(allow_private),
        true,
    )
}

/// Loopback counts as public, so the private-address rules can be tested
/// against local servers.
fn strict_prober() -> Prober {
    let lo: IpAddr = LOOPBACK.parse().unwrap();
    Prober::new(
        Arc::new(Net::new(None).unwrap()),
        Guard::new(false).with_test_exemption(lo),
        true,
    )
}

fn http(url: String) -> Check {
    let mut c = Check::new("mon_test", CheckType::Http);
    c.url = Some(url);
    c.timeout_ms = 2000;
    c
}

#[tokio::test]
async fn http_ok_with_timings() {
    let t = spawn_target().await;
    let r = prober(true).run(&http(format!("http://{t}/ok"))).await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.status_code, Some(200));
    assert_eq!(r.remote_ip.as_deref(), Some(LOOPBACK));
    assert_eq!(r.response_bytes, Some("service is OK".len() as u64));
    let timings = r.timings.unwrap();
    assert_eq!(timings.dns_ms, Some(0));
    assert!(timings.connect_ms.is_some() && timings.ttfb_ms.is_some());
    assert_eq!(timings.tls_ms, None);
    assert!(r.tls_expires_at.is_none());
    assert!(r.started_at.ends_with('Z'));
}

#[tokio::test]
async fn report_ip_false_omits_remote_ip() {
    let t = spawn_target().await;
    let p = Prober::new(Arc::new(Net::new(None).unwrap()), Guard::new(true), false);
    let r = p.run(&http(format!("http://{t}/ok"))).await;
    assert!(r.ok);
    assert!(r.remote_ip.is_none());
}

#[tokio::test]
async fn status_mismatch_and_expected_codes() {
    let t = spawn_target().await;
    let r = prober(true).run(&http(format!("http://{t}/fail"))).await;
    assert!(!r.ok);
    assert_eq!(r.status_code, Some(503));
    assert_eq!(r.error.unwrap().kind, ErrorKind::Status);

    let mut c = http(format!("http://{t}/fail"));
    c.expected_statuses = vec!["503".into()];
    assert!(prober(true).run(&c).await.ok);
}

#[tokio::test]
async fn keyword_present_absent_and_window() {
    let t = spawn_target().await;
    let p = prober(true);
    let mut c = http(format!("http://{t}/ok"));
    c.kind = CheckType::Keyword;
    c.keyword = Some("OK".into());
    assert!(p.run(&c).await.ok);

    c.keyword = Some("ok".into()); // case-sensitive
    let r = p.run(&c).await;
    assert_eq!(r.error.unwrap().kind, ErrorKind::Keyword);

    c.keyword = Some("OK".into());
    c.keyword_absent = true;
    let r = p.run(&c).await;
    assert_eq!(r.error.unwrap().kind, ErrorKind::Keyword);

    c.keyword = Some("maintenance".into());
    assert!(p.run(&c).await.ok);

    // Only the first 1 MiB is read and searched.
    let mut big = http(format!("http://{t}/big"));
    big.kind = CheckType::Keyword;
    big.keyword = Some("needle".into());
    let r = p.run(&big).await;
    assert_eq!(r.error.unwrap().kind, ErrorKind::Keyword);
    assert_eq!(r.response_bytes, Some(1 << 20));
}

#[tokio::test]
async fn follows_redirects_up_to_max() {
    let t = spawn_target().await;
    let p = prober(true);
    let r = p.run(&http(format!("http://{t}/redirect"))).await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.status_code, Some(200));

    let r = p.run(&http(format!("http://{t}/loop"))).await;
    assert_eq!(r.error.unwrap().kind, ErrorKind::Redirects);

    let mut c = http(format!("http://{t}/found"));
    c.max_redirects = 0;
    assert_eq!(p.run(&c).await.error.unwrap().kind, ErrorKind::Redirects);

    // Not following: the 302 itself is judged.
    let mut c = http(format!("http://{t}/found"));
    c.follow_redirects = false;
    let r = p.run(&c).await;
    assert_eq!(r.status_code, Some(302));
    assert_eq!(r.error.unwrap().kind, ErrorKind::Status);
    c.expected_statuses = vec!["3xx".into()];
    assert!(p.run(&c).await.ok);
}

#[tokio::test]
async fn private_rule_applies_to_every_hop() {
    let t = spawn_target().await;
    // First hop is allowed (loopback exempted), the redirect to 10.0.0.1 is not.
    let r = strict_prober()
        .run(&http(format!("http://{t}/to-private")))
        .await;
    let e = r.error.unwrap();
    assert_eq!(e.kind, ErrorKind::Blocked, "{e:?}");
    assert!(r.remote_ip.is_none(), "blocked address is not reported");

    // Without the exemption the first hop is already refused.
    let r = prober(false).run(&http(format!("http://{t}/ok"))).await;
    assert_eq!(r.error.unwrap().kind, ErrorKind::Blocked);

    // The same for tcp and tls checks, and for IPv4-mapped literals.
    let mut c = Check::new("mon_tcp", CheckType::Tcp);
    c.host = Some("::ffff:127.0.0.1".into());
    c.port = Some(t.port());
    assert_eq!(
        prober(false).run(&c).await.error.unwrap().kind,
        ErrorKind::Blocked
    );
    let mut c = http("http://[::ffff:a9fe:a9fe]/latest/meta-data/".into());
    c.timeout_ms = 500;
    assert_eq!(
        prober(false).run(&c).await.error.unwrap().kind,
        ErrorKind::Blocked
    );
}

#[tokio::test]
async fn credentials_are_not_sent_cross_origin() {
    let a = spawn_target().await;
    let b = spawn_target().await;
    let p = prober(true);
    let auth = Some(Auth::Bearer {
        token: "secret".into(),
    });

    // Same origin: credentials kept.
    let mut c = http(format!("http://{a}/to?to=/echo-auth"));
    c.kind = CheckType::Keyword;
    c.keyword = Some("auth=present".into());
    c.auth = auth.clone();
    assert!(p.run(&c).await.ok);

    // Other origin (different port): credentials dropped.
    let mut c = http(format!("http://{a}/to?to=http://{b}/echo-auth"));
    c.kind = CheckType::Keyword;
    c.keyword = Some("auth=none".into());
    c.auth = auth;
    assert!(p.run(&c).await.ok, "Authorization leaked to another origin");
}

#[tokio::test]
async fn method_body_and_headers() {
    let t = spawn_target().await;
    let p = prober(true);
    let mut c = http(format!("http://{t}/echo"));
    c.kind = CheckType::Keyword;
    c.method = "put".into();
    c.body = Some("hello".into());
    c.headers.insert("X-Probe".into(), "1".into());
    c.keyword = Some("method=PUT body=hello x-probe=1".into());
    assert!(p.run(&c).await.ok);

    // 303 after POST continues as GET without the body.
    let mut c = http(format!("http://{t}/post-303"));
    c.kind = CheckType::Keyword;
    c.method = "POST".into();
    c.body = Some("payload".into());
    c.keyword = Some("method=GET body= ".into());
    assert!(p.run(&c).await.ok);

    let mut c = http(format!("http://{t}/ok"));
    c.method = "HEAD".into();
    let r = p.run(&c).await;
    assert!(r.ok);
    assert_eq!(r.response_bytes, Some(0));
}

#[tokio::test]
async fn timeout_and_connect_errors() {
    let t = spawn_target().await;
    let p = prober(true);
    let mut c = http(format!("http://{t}/slow"));
    c.timeout_ms = 300;
    let r = p.run(&c).await;
    assert_eq!(r.error.unwrap().kind, ErrorKind::Timeout);
    assert!(r.duration_ms >= 300 && r.duration_ms < 2000);
    assert!(
        r.timings.unwrap().connect_ms.is_some(),
        "partial timings kept"
    );

    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    // Generous timeouts: Windows retries a refused connection for ~2 s.
    let mut c = http(format!("http://{closed}/"));
    c.timeout_ms = 10_000;
    let r = p.run(&c).await;
    assert_eq!(r.error.unwrap().kind, ErrorKind::Connect);

    let mut c = Check::new("mon_tcp", CheckType::Tcp);
    c.host = Some(LOOPBACK.into());
    c.port = Some(closed.port());
    c.timeout_ms = 10_000;
    assert_eq!(p.run(&c).await.error.unwrap().kind, ErrorKind::Connect);
    c.port = Some(t.port());
    let r = p.run(&c).await;
    assert!(r.ok);
    assert!(r.status_code.is_none() && r.response_bytes.is_none());
}

#[tokio::test]
async fn dns_failure() {
    let mut c = http("http://does-not-exist.invalid/".into());
    c.timeout_ms = 8000;
    let r = prober(false).run(&c).await;
    let kind = r.error.unwrap().kind;
    // Without network access the lookup may time out instead.
    assert!(
        matches!(kind, ErrorKind::Dns | ErrorKind::Timeout),
        "{kind:?}"
    );
}

#[tokio::test]
async fn tls_expiry_and_verification() {
    let in_90_days = OffsetDateTime::now_utc() + time::Duration::days(90);
    let s = spawn_tls(in_90_days).await;
    let p = prober(true);

    // tls check, self-signed: verification fails but the expiry is still reported.
    let mut c = Check::new("mon_tls", CheckType::Tls);
    c.host = Some("localhost".into());
    c.port = Some(s.port());
    c.timeout_ms = 3000;
    let r = p.run(&c).await;
    assert_eq!(r.error.as_ref().unwrap().kind, ErrorKind::Tls);
    let exp = r.tls_expires_at.expect("expiry reported");
    assert!(exp.starts_with(&in_90_days.year().to_string()));

    c.verify_tls = false;
    let r = p.run(&c).await;
    assert!(r.ok, "{r:?}");
    assert!(r.tls_expires_at.is_some());
    assert!(r.timings.unwrap().tls_ms.is_some());

    // https http check reports tls_expires_at too.
    let mut c = http(format!("https://localhost:{}/", s.port()));
    c.verify_tls = false;
    let r = p.run(&c).await;
    assert!(r.ok, "{r:?}");
    assert!(r.tls_expires_at.is_some());
    c.verify_tls = true;
    assert_eq!(p.run(&c).await.error.unwrap().kind, ErrorKind::Tls);
}

#[tokio::test]
async fn expired_certificate_fails_tls_check() {
    let expired = OffsetDateTime::now_utc() - time::Duration::days(3);
    let s = spawn_tls(expired).await;
    let mut c = Check::new("mon_tls", CheckType::Tls);
    c.url = Some(format!("https://localhost:{}", s.port()));
    c.verify_tls = false;
    c.timeout_ms = 3000;
    let r = prober(true).run(&c).await;
    let e = r.error.unwrap();
    assert_eq!(e.kind, ErrorKind::Tls);
    assert!(e.message.contains("expired"), "{}", e.message);
    assert!(r.tls_expires_at.is_some());
}

fn proxied(url: &str) -> Prober {
    let settings =
        bynh_status_agent::proxy::ProxySettings::resolve(Some(url), Some(""), &|_| None).unwrap();
    Prober::new(Arc::new(Net::new(None).unwrap()), Guard::new(true), true).with_proxy(settings)
}

#[tokio::test]
async fn checks_through_a_connect_proxy() {
    let (proxy, log) = common::spawn_proxy(None).await;
    let tls = spawn_tls(OffsetDateTime::now_utc() + time::Duration::days(30)).await;
    let target = spawn_target().await;
    let p = proxied(&format!("http://{proxy}"));

    // https through a CONNECT tunnel
    let mut c = http(format!("https://localhost:{}/", tls.port()));
    c.verify_tls = false;
    let r = p.run(&c).await;
    assert!(r.ok, "{r:?}");
    assert!(r.tls_expires_at.is_some());
    assert!(
        r.remote_ip.is_none(),
        "the target's IP is unknown through a proxy"
    );

    // plain http in absolute form
    let r = p.run(&http(format!("http://{target}/ok"))).await;
    assert!(r.ok, "{r:?}");

    // tcp through a tunnel
    let mut c = Check::new("mon_tcp", CheckType::Tcp);
    c.host = Some(LOOPBACK.into());
    c.port = Some(target.port());
    assert!(p.run(&c).await.ok);

    let log = log.lock().unwrap().clone();
    assert!(
        log.contains(&format!("CONNECT localhost:{} HTTP/1.1", tls.port())),
        "{log:?}"
    );
    assert!(
        log.contains(&format!("GET http://{target}/ok HTTP/1.1")),
        "{log:?}"
    );
    assert!(
        log.contains(&format!("CONNECT 127.0.0.1:{} HTTP/1.1", target.port())),
        "{log:?}"
    );
}

#[tokio::test]
async fn proxy_authentication() {
    // "user:p@ss" → dXNlcjpwQHNz
    let (proxy, _) = common::spawn_proxy(Some("Basic dXNlcjpwQHNz")).await;
    let target = spawn_target().await;
    let mut c = http(format!(
        "https://localhost:{}/",
        spawn_tls(OffsetDateTime::now_utc() + time::Duration::days(30))
            .await
            .port()
    ));
    c.verify_tls = false;

    let ok = proxied(&format!("http://user:p%40ss@{proxy}"));
    assert!(ok.run(&c).await.ok);
    assert!(ok.run(&http(format!("http://{target}/ok"))).await.ok);

    let r = proxied(&format!("http://{proxy}")).run(&c).await;
    let e = r.error.unwrap();
    assert_eq!(e.kind, ErrorKind::Connect);
    assert!(e.message.contains("407"), "{}", e.message);
    assert!(!e.message.contains("p@ss") && !e.message.contains("p%40ss"));
}

#[tokio::test]
async fn no_proxy_connects_directly() {
    let (proxy, log) = common::spawn_proxy(None).await;
    let target = spawn_target().await;
    let settings = bynh_status_agent::proxy::ProxySettings::resolve(
        Some(&format!("http://{proxy}")),
        Some("127.0.0.1"),
        &|_| None,
    )
    .unwrap();
    let p =
        Prober::new(Arc::new(Net::new(None).unwrap()), Guard::new(true), true).with_proxy(settings);
    let r = p.run(&http(format!("http://{target}/ok"))).await;
    assert!(r.ok);
    assert_eq!(r.remote_ip.as_deref(), Some(LOOPBACK));
    assert!(log.lock().unwrap().is_empty());
}
