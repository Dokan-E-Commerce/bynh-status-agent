//! End-to-end: the agent against a mock platform and local targets.

mod common;

use std::collections::HashSet;
use std::time::Duration;

use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{agent_for, http_check, ids, spawn_platform, spawn_target, wait_for, TOKEN};

#[tokio::test]
async fn hello_assignments_304_and_results() {
    let (platform, mock) = spawn_platform().await;
    let target = spawn_target().await;
    {
        let mut s = mock.lock().unwrap();
        s.max_batch = 2;
        s.checks = json!([
            http_check("mon_ok", &format!("http://{target}/ok")),
            http_check("mon_down", &format!("http://{target}/fail")),
            { "id": "mon_tcp", "type": "tcp", "host": "127.0.0.1", "port": target.port(), "interval_seconds": 1, "timeout_ms": 1000 },
            { "id": "mon_unknown", "type": "smtp", "host": "mail.example.com" }
        ]);
    }
    let shutdown = CancellationToken::new();
    let run = tokio::spawn(agent_for(platform).run(shutdown.clone()));

    let got = wait_for(&mock, Duration::from_secs(8), |s| {
        let seen: HashSet<String> = s
            .results_calls
            .iter()
            .flat_map(|c| ids(&c.results))
            .collect();
        seen.len() >= 3
            && s.assignment_calls
                .iter()
                .filter(|c| c.status == 304)
                .count()
                >= 2
    })
    .await;
    shutdown.cancel();
    run.await.unwrap();
    assert!(got, "did not see results and 304 polls in time");

    let s = mock.lock().unwrap();
    // hello first, with the protocol headers
    assert_eq!(s.hello_calls.len(), 1);
    let h = &s.hello_calls[0].headers;
    assert_eq!(h["authorization"], format!("Bearer {TOKEN}").as_str());
    assert_eq!(h["x-bynh-status-agent-protocol"], "1");
    let ua = h["user-agent"].to_str().unwrap();
    assert!(
        ua.starts_with("bynh-status-agent/1.") && ua.contains("; "),
        "{ua}"
    );
    assert!(s.hello_calls[0].at <= s.assignment_calls[0].at);

    // first poll has no If-None-Match, later ones echo the ETag and get 304
    assert!(s.assignment_calls[0].headers.get("if-none-match").is_none());
    assert_eq!(s.assignment_calls[0].status, 200);
    for c in &s.assignment_calls[1..] {
        assert_eq!(c.headers["if-none-match"], "\"c_1\"");
        assert_eq!(c.status, 304);
    }

    // results: gzip, batches of at most max_batch, correct outcomes
    for c in &s.results_calls {
        assert_eq!(c.call.headers["content-encoding"], "gzip");
        assert!(c.results.len() <= 2, "batch of {}", c.results.len());
    }
    let all: Vec<_> = s
        .results_calls
        .iter()
        .flat_map(|c| c.results.clone())
        .collect();
    let find = |id: &str| all.iter().find(|r| r["check_id"] == id).unwrap().clone();
    let ok = find("mon_ok");
    assert_eq!(ok["ok"], true);
    assert_eq!(ok["status_code"], 200);
    assert_eq!(ok["remote_ip"], "127.0.0.1");
    assert!(ok["timings"]["connect_ms"].is_u64());
    let down = find("mon_down");
    assert_eq!(down["ok"], false);
    assert_eq!(down["error"]["kind"], "status");
    assert_eq!(find("mon_tcp")["ok"], true);
    assert!(!all.iter().any(|r| r["check_id"] == "mon_unknown"));
}

#[tokio::test]
async fn unauthorized_stops_checks_and_retries_hello() {
    let (platform, mock) = spawn_platform().await;
    let target = spawn_target().await;
    {
        let mut s = mock.lock().unwrap();
        s.hello_status = 401;
        s.checks = json!([http_check("mon_ok", &format!("http://{target}/ok"))]);
    }
    let shutdown = CancellationToken::new();
    let run = tokio::spawn(agent_for(platform).run(shutdown.clone()));

    // retries hello on the auth_retry interval and never polls meanwhile
    assert!(wait_for(&mock, Duration::from_secs(5), |s| s.hello_calls.len() >= 3).await);
    {
        let s = mock.lock().unwrap();
        assert!(s.assignment_calls.is_empty());
        let gap = s.hello_calls[2].at - s.hello_calls[1].at;
        assert!(gap >= Duration::from_millis(350), "retried after {gap:?}");
    }

    // token works again → normal operation
    mock.lock().unwrap().hello_status = 200;
    assert!(
        wait_for(&mock, Duration::from_secs(6), |s| !s
            .results_calls
            .is_empty())
        .await
    );

    // 401 mid-session on assignments: checks stop, back to hello
    {
        let mut s = mock.lock().unwrap();
        s.assignments_status = 401;
        s.hello_status = 401;
    }
    let hellos_before = mock.lock().unwrap().hello_calls.len();
    assert!(
        wait_for(&mock, Duration::from_secs(5), |s| s.hello_calls.len()
            > hellos_before)
        .await
    );
    // Give in-flight work a moment, then make sure no new results arrive.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let results_then = mock.lock().unwrap().results_calls.len();
    tokio::time::sleep(Duration::from_millis(2000)).await;
    assert_eq!(mock.lock().unwrap().results_calls.len(), results_then);

    // recovery fetches the full assignment set again (no stale ETag)
    {
        let mut s = mock.lock().unwrap();
        s.assignments_status = 200;
        s.hello_status = 200;
    }
    let polls_before = mock.lock().unwrap().assignment_calls.len();
    assert!(
        wait_for(&mock, Duration::from_secs(5), |s| s.assignment_calls.len()
            > polls_before)
        .await
    );
    {
        let s = mock.lock().unwrap();
        let first_after = &s.assignment_calls[polls_before];
        assert!(first_after.headers.get("if-none-match").is_none());
        assert_eq!(first_after.status, 200);
    }
    shutdown.cancel();
    run.await.unwrap();
}

#[tokio::test]
async fn upgrade_required_retries_on_the_upgrade_interval() {
    let (platform, mock) = spawn_platform().await;
    mock.lock().unwrap().hello_status = 426;
    let shutdown = CancellationToken::new();
    let run = tokio::spawn(agent_for(platform).run(shutdown.clone()));
    assert!(wait_for(&mock, Duration::from_secs(5), |s| s.hello_calls.len() >= 3).await);
    {
        let s = mock.lock().unwrap();
        assert!(s.assignment_calls.is_empty());
        for w in s.hello_calls.windows(2) {
            assert!(w[1].at - w[0].at >= Duration::from_millis(350));
        }
    }
    mock.lock().unwrap().hello_status = 200;
    assert!(
        wait_for(&mock, Duration::from_secs(5), |s| !s
            .assignment_calls
            .is_empty())
        .await
    );
    shutdown.cancel();
    run.await.unwrap();
}

#[tokio::test]
async fn rate_limit_honours_retry_after_and_keeps_results() {
    let (platform, mock) = spawn_platform().await;
    let target = spawn_target().await;
    {
        let mut s = mock.lock().unwrap();
        s.checks = json!([http_check("mon_ok", &format!("http://{target}/ok"))]);
        s.results_script.push_back((429, Some("2".into())));
        s.results_script.push_back((503, None));
    }
    let shutdown = CancellationToken::new();
    let run = tokio::spawn(agent_for(platform).run(shutdown.clone()));
    assert!(
        wait_for(&mock, Duration::from_secs(10), |s| s
            .results_calls
            .iter()
            .any(|c| c.call.status == 202))
        .await
    );
    shutdown.cancel();
    run.await.unwrap();

    let s = mock.lock().unwrap();
    let c = &s.results_calls;
    assert_eq!(c[0].call.status, 429);
    assert_eq!(c[1].call.status, 503);
    let gap = c[1].call.at - c[0].call.at;
    assert!(
        gap >= Duration::from_millis(1900),
        "Retry-After ignored: {gap:?}"
    );
    // The results refused with 429 are delivered later (nothing lost).
    let first = &c[0].results[0]["started_at"];
    let delivered: Vec<_> = c
        .iter()
        .filter(|c| c.call.status == 202)
        .flat_map(|c| c.results.iter().map(|r| r["started_at"].clone()))
        .collect();
    assert!(delivered.contains(first));
}

#[tokio::test]
async fn assignment_changes_add_and_remove_checks() {
    let (platform, mock) = spawn_platform().await;
    let target = spawn_target().await;
    mock.lock().unwrap().checks = json!([http_check("mon_a", &format!("http://{target}/ok"))]);
    let shutdown = CancellationToken::new();
    let run = tokio::spawn(agent_for(platform).run(shutdown.clone()));

    let seen = |id: &'static str| {
        move |s: &common::MockState| {
            s.results_calls
                .iter()
                .any(|c| ids(&c.results).iter().any(|x| x == id))
        }
    };
    assert!(wait_for(&mock, Duration::from_secs(6), seen("mon_a")).await);

    {
        let mut s = mock.lock().unwrap();
        s.config_version = "c_2".into();
        s.checks = json!([http_check("mon_b", &format!("http://{target}/ok"))]);
    }
    assert!(wait_for(&mock, Duration::from_secs(6), seen("mon_b")).await);
    // Let anything already buffered for mon_a drain, then it must stop.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let mark = mock.lock().unwrap().results_calls.len();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    shutdown.cancel();
    run.await.unwrap();

    let s = mock.lock().unwrap();
    let later: Vec<String> = s.results_calls[mark..]
        .iter()
        .flat_map(|c| ids(&c.results))
        .collect();
    assert!(!later.is_empty());
    assert!(later.iter().all(|id| id == "mon_b"), "{later:?}");
    assert!(s.assignment_calls.iter().any(|c| c
        .headers
        .get("if-none-match")
        .map(|v| v == "\"c_1\"")
        .unwrap_or(false)
        && c.status == 200));
}

#[tokio::test]
async fn shutdown_flushes_buffered_results() {
    let (platform, mock) = spawn_platform().await;
    let target = spawn_target().await;
    {
        let mut s = mock.lock().unwrap();
        s.report_interval = 3600; // nothing is reported during the run
        s.checks = json!([
            http_check("mon_a", &format!("http://{target}/ok")),
            http_check("mon_b", &format!("http://{target}/ok"))
        ]);
    }
    let agent = agent_for(platform);
    let buffer = agent.buffer();
    let shutdown = CancellationToken::new();
    let run = tokio::spawn(agent.run(shutdown.clone()));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    while buffer.len() < 3 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(mock.lock().unwrap().results_calls.is_empty());
    let buffered = buffer.len();
    assert!(buffered >= 3);

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("shutdown within the flush deadline")
        .unwrap();
    let s = mock.lock().unwrap();
    let sent: usize = s.results_calls.iter().map(|c| c.results.len()).sum();
    assert!(sent >= buffered, "sent {sent} of {buffered}");
    assert!(buffer.is_empty());
}
