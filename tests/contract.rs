//! Pins the agent's wire names to PROTOCOL.md, so a rename in one place
//! can't silently break the contract with the platform.

use bynh_status_agent::config::DEFAULT_API_URL;
use bynh_status_agent::protocol::{
    user_agent, ErrorKind, AGENT_VERSION, METHODS, PATH_ASSIGNMENTS, PATH_HELLO, PATH_RESULTS,
    PROTOCOL_HEADER, PROTOCOL_VERSION,
};

const PROTOCOL_RAW: &str = include_str!("../PROTOCOL.md");

/// PROTOCOL.md with LF line endings, whatever the checkout did (Windows can check it out as CRLF).
static PROTOCOL_LF: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| PROTOCOL_RAW.replace("\r\n", "\n"));

fn line_with(needle: &str) -> &'static str {
    PROTOCOL_LF
        .lines()
        .find(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("PROTOCOL.md has no line containing {needle:?}"))
}

#[test]
fn protocol_header() {
    assert_eq!(PROTOCOL_HEADER, "X-Bynh-Agent-Protocol");
    assert!(PROTOCOL_LF.contains(&format!("`{PROTOCOL_HEADER}: {PROTOCOL_VERSION}`")));
    assert!(PROTOCOL_LF.contains("`Authorization: Bearer <token>`"));
}

#[test]
fn endpoint_paths() {
    assert!(PROTOCOL_LF.contains(&format!("### POST {PATH_HELLO}\n")));
    assert!(PROTOCOL_LF.contains(&format!("### GET {PATH_ASSIGNMENTS}\n")));
    assert!(PROTOCOL_LF.contains(&format!("### POST {PATH_RESULTS}\n")));
    assert!(PROTOCOL_LF.contains(&format!("Base URL default `{DEFAULT_API_URL}`")));
}

#[test]
fn user_agent_format() {
    assert!(PROTOCOL_LF.contains("`User-Agent: bynh-status-agent/<version> (<os>; <arch>)`"));
    let ua = user_agent();
    let expected = format!(
        "bynh-status-agent/{AGENT_VERSION} ({}; {})",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    assert_eq!(ua, expected);
}

#[test]
fn methods_match() {
    let line = line_with("\"method\":");
    for m in METHODS {
        assert!(
            line.contains(&format!("\"{m}\"")),
            "{m} missing from {line}"
        );
    }
    assert_eq!(line.matches("\" | \"").count() + 1, METHODS.len());
}

#[test]
fn error_kinds_match() {
    let line = line_with("\"kind\": \"dns\"");
    let kinds = [
        ErrorKind::Dns,
        ErrorKind::Connect,
        ErrorKind::Timeout,
        ErrorKind::Tls,
        ErrorKind::Status,
        ErrorKind::Keyword,
        ErrorKind::Redirects,
        ErrorKind::Blocked,
        ErrorKind::Other,
    ];
    for k in kinds {
        let name = serde_json::to_string(&k).unwrap();
        assert!(line.contains(&name), "{name} missing from {line}");
    }
}

#[test]
fn check_types_match() {
    let line = line_with("\"type\": \"http\"");
    for t in ["http", "keyword", "tcp", "tls"] {
        assert!(line.contains(&format!("\"{t}\"")));
    }
}

// ---------------------------------------------------------------------------
// Check details (agent 1.1.0)

use bynh_status_agent::details::{
    BodyDetails, DetailTimings, Details, RedirectHop, RequestInfo, TlsDetails, REDACT_ALWAYS,
    REDACT_EXEMPT, REDACT_PARTS,
};

/// The `details` example in the "Check details" section of PROTOCOL.md.
fn details_block() -> &'static str {
    let section = PROTOCOL_LF
        .split("## Check details (agent 1.1.0)\n")
        .nth(1)
        .expect("PROTOCOL.md has a Check details section");
    let start = section.find("```json\n").expect("details example") + "```json\n".len();
    let end = start + section[start..].find("```").unwrap();
    &section[start..end]
}

/// Keys written as `"name":` in a piece of the document.
fn documented_keys(text: &str) -> std::collections::BTreeSet<String> {
    let b = text.as_bytes();
    let mut keys = std::collections::BTreeSet::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            let rest = &text[i + 1..];
            let len = rest
                .bytes()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
                .count();
            if len > 0 && rest[len..].starts_with("\":") {
                keys.insert(rest[..len].to_owned());
                i += len + 2;
                continue;
            }
        }
        i += 1;
    }
    keys
}

/// Every object key in a JSON value, recursively.
fn serialised_keys(v: &serde_json::Value, out: &mut std::collections::BTreeSet<String>) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, v) in m {
                out.insert(k.clone());
                serialised_keys(v, out);
            }
        }
        serde_json::Value::Array(a) => a.iter().for_each(|v| serialised_keys(v, out)),
        _ => {}
    }
}

/// Details with every optional field present.
fn full_details() -> Details {
    Details {
        http_version: Some("HTTP/1.1"),
        ip_family: Some("4"),
        request: Some(RequestInfo {
            method: "GET".into(),
            url: "https://shop.example.com/health".into(),
        }),
        status_text: Some("OK".into()),
        response_headers: vec![("server".into(), "nginx".into())],
        body: Some(BodyDetails {
            sample: Some("ok".into()),
            sample_base64: false,
            truncated: false,
            size: Some(2),
            sha256: Some("00".into()),
            content_type: Some("text/plain".into()),
            sample_omitted: Some("unchanged"),
        }),
        redirects: vec![RedirectHop {
            url: "https://shop.example.com/health".into(),
            status: 301,
            duration_ms: 41,
            remote_ip: Some("203.0.113.5".into()),
        }],
        tls: Some(TlsDetails {
            protocol: Some("TLSv1.3".into()),
            cipher: Some("TLS13_AES_256_GCM_SHA384".into()),
            subject: Some("CN=shop.example.com".into()),
            issuer: Some("CN=R11".into()),
            sans: vec!["shop.example.com".into()],
            not_before: Some("2026-09-01T00:00:00.000Z".into()),
            not_after: Some("2026-11-30T23:59:59.000Z".into()),
            fingerprint_sha256: Some("00".into()),
            chain_length: 2,
            verified: true,
            verify_error: None,
        }),
        timings: Some(DetailTimings {
            dns_ms: Some(5),
            connect_ms: Some(20),
            tls_ms: Some(40),
            ttfb_ms: Some(150),
            download_ms: Some(30),
            total_ms: Some(250),
        }),
    }
}

#[test]
fn details_fields_match() {
    let mut doc = documented_keys(details_block());
    assert!(doc.remove("details"));
    let mut ser = std::collections::BTreeSet::new();
    serialised_keys(&serde_json::to_value(full_details()).unwrap(), &mut ser);
    assert_eq!(
        doc, ser,
        "PROTOCOL.md details example and the agent disagree"
    );
    assert!(details_block().trim_start().starts_with("\"details\": {"));
    assert!(line_with("\"response_bytes\":").contains("1234"));
    assert!(PROTOCOL_LF.contains("\"details\": { … } }"));
}

#[test]
fn capture_body_is_documented_and_parsed() {
    let line = line_with("\"capture_body\":");
    assert!(line.contains("default true"), "{line}");
    let doc = br#"{ "config_version": "c", "checks": [
        { "id": "a", "type": "http", "url": "https://example.com/", "capture_body": false },
        { "id": "b", "type": "http", "url": "https://example.com/" } ] }"#;
    let a = bynh_status_agent::protocol::Assignments::parse(doc).unwrap();
    assert!(!a.checks[0].capture_body);
    assert!(a.checks[1].capture_body);
}

#[test]
fn redaction_list_matches() {
    let rules = PROTOCOL_LF
        .split("**Redaction on the agent**")
        .nth(1)
        .expect("redaction rule")
        .split("\n- **")
        .next()
        .unwrap();
    for name in REDACT_ALWAYS
        .iter()
        .chain(REDACT_PARTS)
        .chain(REDACT_EXEMPT)
    {
        assert!(
            rules.contains(&format!("`{name}`")),
            "{name} not documented"
        );
    }
    let documented = rules.matches('`').count() / 2;
    assert_eq!(
        documented,
        REDACT_ALWAYS.len() + REDACT_PARTS.len() + REDACT_EXEMPT.len() + 2,
        "PROTOCOL.md lists names the agent doesn't (+2: the placeholder and the monitor's `auth`): {rules}"
    );
}

// ---------------------------------------------------------------------------
// Round robin (agent 1.2.0)

use bynh_status_agent::protocol::{limits, Assignments, CheckResult, HelloResponse, Schedule};
use bynh_status_agent::scheduler::{CONFIRM_MIN_GAP, MAX_JITTER_MS, NONCE_MEMORY};

fn round_robin_section() -> &'static str {
    PROTOCOL_LF
        .split("## Round robin (agent 1.2.0)\n")
        .nth(1)
        .expect("PROTOCOL.md has a Round robin section")
}

/// The first ```json block after `heading` in the Round robin section.
fn rr_block(heading: &str) -> &'static str {
    let section = round_robin_section();
    let at = section
        .find(heading)
        .unwrap_or_else(|| panic!("no {heading}"));
    let rest = &section[at..];
    let start = rest.find("```json\n").expect("example") + "```json\n".len();
    &rest[start..start + rest[start..].find("```").unwrap()]
}

#[test]
fn schedule_fields_match() {
    let block = rr_block("### `schedule`");
    let doc = documented_keys(block);
    let mut ser = std::collections::BTreeSet::new();
    let schedule = Schedule {
        every_seconds: 300,
        phase_seconds: 137,
        epoch: 0,
    };
    serialised_keys(
        &serde_json::json!({ "schedule": serde_json::to_value(schedule).unwrap() }),
        &mut ser,
    );
    assert_eq!(doc, ser);
    // The example parses as a check's schedule.
    let check = format!(
        r#"{{ "config_version": "c", "checks": [{{ "id": "mon_1", "type": "http", "url": "https://example.com/", {} }}] }}"#,
        block.trim()
    );
    let a = Assignments::parse(check.as_bytes()).unwrap();
    assert_eq!(a.checks[0].schedule, Some(schedule));
    let section = round_robin_section();
    assert!(section.contains("`(t − epoch − phase_seconds) mod every_seconds == 0`"));
    assert!(section.contains(&format!("at most {} s", MAX_JITTER_MS / 1000)));
    assert!(section.contains(&format!(
        "`interval_seconds`–{} (a week)",
        group(limits::MAX_EVERY_SECONDS)
    )));
}

#[test]
fn confirm_fields_match() {
    let block = rr_block("### `confirm`");
    assert_eq!(
        documented_keys(block),
        ["check_id", "confirm", "nonce", "requested_at"]
            .map(String::from)
            .into()
    );
    let doc = format!(r#"{{ "config_version": "c", {} }}"#, block.trim());
    let a = Assignments::parse(doc.replace("…32 chars", "").as_bytes()).unwrap();
    assert_eq!(a.confirm.len(), 1);
    assert_eq!(a.confirm[0].check_id, "mon_123");

    let section = round_robin_section();
    assert!(section.contains(&format!("at least {} minutes", NONCE_MEMORY.as_secs() / 60)));
    assert!(section.contains(&format!("per check\n  per {} s", CONFIRM_MIN_GAP.as_secs())));
    assert!(section.contains(&format!(
        "At most {} requests",
        group(limits::MAX_CONFIRM as u64)
    )));
    assert!(section.contains(&format!("`nonce` is\n  1–{} characters", limits::MAX_NONCE)));
}

#[test]
fn confirm_nonce_and_long_poll_match() {
    assert!(line_with("### `confirm_nonce`").contains("(results, per result)"));
    assert!(round_robin_section().contains("`\"confirm_nonce\": \"Zt7…\"`"));
    let r = CheckResult {
        check_id: "mon_1".into(),
        started_at: "2026-10-03T05:00:00.000Z".into(),
        duration_ms: 1,
        ok: true,
        status_code: None,
        error: None,
        timings: None,
        tls_expires_at: None,
        remote_ip: None,
        response_bytes: None,
        details: None,
        confirm_nonce: Some("Zt7".into()),
    };
    assert_eq!(serde_json::to_value(&r).unwrap()["confirm_nonce"], "Zt7");

    assert!(PROTOCOL_LF.contains("`\"long_poll_seconds\": 25`"));
    assert!(PROTOCOL_LF.contains(&format!("`GET {PATH_ASSIGNMENTS}?wait=N`")));
    let h: HelloResponse =
        serde_json::from_str(r#"{ "agent": { "id": "agt_1" }, "long_poll_seconds": 25 }"#).unwrap();
    assert_eq!(h.long_poll_seconds, Some(25));
    assert!(round_robin_section().contains(&format!(
        "at least N + {} s",
        bynh_status_agent::platform::LONG_POLL_MARGIN_SECS
    )));
}

/// 604800 → "604,800".
fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}
