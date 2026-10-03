//! Round robin end to end (agent 1.2.0): schedules on the wall clock, confirmation requests and
//! long-poll, against the mock platform.

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use bynh_status_agent::scheduler::jitter_ms;
use common::{agent_for, http_check, spawn_platform, spawn_target, wait_for, MockState};

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A check whose turn is half an hour away, so only confirmations run it.
fn far_check(id: &str, url: &str) -> Value {
    let mut c = http_check(id, url);
    c["interval_seconds"] = json!(60);
    c["schedule"] =
        json!({ "every_seconds": 3600, "phase_seconds": (unix_secs() + 1800) % 3600, "epoch": 0 });
    c
}

fn results_for<'a>(s: &'a MockState, id: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
    s.results_calls
        .iter()
        .flat_map(|c| c.results.iter())
        .filter(move |r| r["check_id"] == id)
}

fn millis_of(started_at: &str) -> u64 {
    let t = time::OffsetDateTime::parse(started_at, &time::format_description::well_known::Rfc3339)
        .unwrap();
    u64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap()
}

#[tokio::test]
async fn scheduled_checks_run_on_the_wall_clock_grid() {
    let (platform, mock) = spawn_platform().await;
    let target = spawn_target().await;
    let mut check = http_check("mon_rr", &format!("http://{target}/ok"));
    check["schedule"] = json!({ "every_seconds": 2, "phase_seconds": 1, "epoch": 0 });
    mock.lock().unwrap().checks = json!([check]);
    let shutdown = CancellationToken::new();
    let run = tokio::spawn(agent_for(platform).run(shutdown.clone()));

    let got = wait_for(&mock, Duration::from_secs(10), |s| {
        results_for(s, "mon_rr").count() >= 3
    })
    .await;
    shutdown.cancel();
    run.await.unwrap();
    assert!(got, "no scheduled results");

    // Every two seconds, on odd seconds plus the check's fixed jitter (under a second here).
    let jitter = jitter_ms("mon_rr", 2_000);
    assert!(jitter < 1_000);
    let s = mock.lock().unwrap();
    let starts: Vec<u64> = results_for(&s, "mon_rr")
        .map(|r| millis_of(r["started_at"].as_str().unwrap()))
        .collect();
    for t in &starts {
        let late = (t + 2_000 - 1_000 - jitter) % 2_000;
        assert!(late < 150, "started {late} ms off its slot: {starts:?}");
    }
    for w in starts.windows(2) {
        let gap = w[1] - w[0];
        assert!((1_850..=2_150).contains(&gap), "{starts:?}");
    }
}

#[tokio::test]
async fn long_polls_pick_up_confirmations_at_once_and_run_each_nonce_once() {
    let (platform, mock) = spawn_platform().await;
    let target = spawn_target().await;
    {
        let mut s = mock.lock().unwrap();
        s.long_poll_seconds = Some(2);
        s.poll_interval = 15;
        s.checks = json!([far_check("mon_c", &format!("http://{target}/fail"))]);
    }
    let shutdown = CancellationToken::new();
    let run = tokio::spawn(agent_for(platform).run(shutdown.clone()));

    // The agent holds a long poll open on the platform.
    assert!(
        wait_for(&mock, Duration::from_secs(8), |s| s
            .assignment_calls
            .iter()
            .any(|c| c.status == 304))
        .await
    );
    {
        let s = mock.lock().unwrap();
        assert!(s
            .assignment_calls
            .iter()
            .all(|c| c.query.as_deref() == Some("wait=2")));
        let held = s.assignment_calls.iter().find(|c| c.status == 304).unwrap();
        assert!(
            held.done - held.at >= Duration::from_millis(1_900),
            "not held"
        );
        assert!(
            results_for(&s, "mon_c").next().is_none(),
            "its turn is far away"
        );
    }

    // A confirmation request: the held poll answers, the check runs once, with the nonce.
    let asked = tokio::time::Instant::now();
    {
        let mut s = mock.lock().unwrap();
        s.confirm = json!([{ "check_id": "mon_c", "requested_at": "2026-10-03T05:00:02.000Z", "nonce": "n1" }]);
        s.config_version = "c_2".into();
    }
    assert!(
        wait_for(&mock, Duration::from_secs(8), |s| results_for(s, "mon_c")
            .count()
            == 1)
        .await
    );
    let took = tokio::time::Instant::now() - asked;
    assert!(
        took < Duration::from_secs(3),
        "confirmation took {took:?} (report interval 1 s)"
    );

    // The platform keeps listing it (and a new version comes along): it never runs again; a
    // request for a check that isn't assigned is ignored.
    {
        let mut s = mock.lock().unwrap();
        s.confirm = json!([
            { "check_id": "mon_c", "nonce": "n1" },
            { "check_id": "mon_unknown", "nonce": "n3" }
        ]);
        s.config_version = "c_3".into();
    }
    assert!(
        wait_for(&mock, Duration::from_secs(4), |s| s
            .assignment_calls
            .iter()
            .any(
                |c| c.status == 200 && c.done > asked + Duration::from_millis(500)
            ))
        .await
    );
    tokio::time::sleep(Duration::from_millis(2_000)).await;
    shutdown.cancel();
    run.await.unwrap();

    let s = mock.lock().unwrap();
    let nonces: Vec<&Value> = results_for(&s, "mon_c")
        .map(|r| &r["confirm_nonce"])
        .collect();
    assert_eq!(nonces, [&json!("n1")]);
    assert!(results_for(&s, "mon_unknown").next().is_none());
    let first = results_for(&s, "mon_c").next().unwrap();
    assert_eq!(first["ok"], false);
    assert_eq!(first["error"]["kind"], "status");
    // Held polls, not a poll every second: about one per two seconds.
    let polls = s.assignment_calls.len();
    assert!(polls <= 10, "{polls} polls");
}

#[tokio::test]
async fn without_long_poll_the_agent_polls_plainly_and_still_confirms() {
    let (platform, mock) = spawn_platform().await;
    let target = spawn_target().await;
    {
        let mut s = mock.lock().unwrap();
        s.checks = json!([far_check("mon_c", &format!("http://{target}/ok"))]);
        s.confirm = json!([{ "check_id": "mon_c", "nonce": "n1" }]);
    }
    let shutdown = CancellationToken::new();
    let run = tokio::spawn(agent_for(platform).run(shutdown.clone()));
    assert!(
        wait_for(&mock, Duration::from_secs(8), |s| results_for(s, "mon_c")
            .count()
            == 1)
        .await
    );
    assert!(
        wait_for(&mock, Duration::from_secs(5), |s| s.assignment_calls.len()
            >= 3)
        .await
    );
    shutdown.cancel();
    run.await.unwrap();

    let s = mock.lock().unwrap();
    assert!(s.assignment_calls.iter().all(|c| c.query.is_none()));
    assert_eq!(results_for(&s, "mon_c").count(), 1);
    assert_eq!(
        results_for(&s, "mon_c").next().unwrap()["confirm_nonce"],
        "n1"
    );
}

#[tokio::test]
async fn a_poll_the_platform_did_not_hold_falls_back_to_the_poll_interval() {
    let (platform, mock) = spawn_platform().await;
    {
        let mut s = mock.lock().unwrap();
        // Long-poll offered, but the platform answers at once (it had no room).
        s.long_poll_seconds = Some(20);
        s.hold = false;
        s.poll_interval = 2;
    }
    let shutdown = CancellationToken::new();
    let run = tokio::spawn(agent_for(platform).run(shutdown.clone()));
    assert!(
        wait_for(&mock, Duration::from_secs(6), |s| s.assignment_calls.len()
            >= 3)
        .await
    );
    shutdown.cancel();
    run.await.unwrap();

    let s = mock.lock().unwrap();
    let c = &s.assignment_calls;
    assert_eq!((c[0].status, c[1].status, c[2].status), (200, 304, 304));
    // After the 200, straight away (that poll is the one a platform would hold) …
    assert!(c[1].at - c[0].done < Duration::from_millis(1_000));
    // … after a 304 that came back fast, the poll interval.
    assert!(c[2].at - c[1].done >= Duration::from_millis(1_900));
}
