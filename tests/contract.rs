//! Pins the agent's wire names to PROTOCOL.md, so a rename in one place
//! can't silently break the contract with the platform.

use bynh_status_agent::config::DEFAULT_API_URL;
use bynh_status_agent::protocol::{
    user_agent, ErrorKind, AGENT_VERSION, METHODS, PATH_ASSIGNMENTS, PATH_HELLO, PATH_RESULTS,
    PROTOCOL_HEADER, PROTOCOL_VERSION,
};

const PROTOCOL: &str = include_str!("../PROTOCOL.md");

fn line_with(needle: &str) -> &'static str {
    PROTOCOL
        .lines()
        .find(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("PROTOCOL.md has no line containing {needle:?}"))
}

#[test]
fn protocol_header() {
    assert_eq!(PROTOCOL_HEADER, "X-Bynh-Agent-Protocol");
    assert!(PROTOCOL.contains(&format!("`{PROTOCOL_HEADER}: {PROTOCOL_VERSION}`")));
    assert!(PROTOCOL.contains("`Authorization: Bearer <token>`"));
}

#[test]
fn endpoint_paths() {
    assert!(PROTOCOL.contains(&format!("### POST {PATH_HELLO}\n")));
    assert!(PROTOCOL.contains(&format!("### GET {PATH_ASSIGNMENTS}\n")));
    assert!(PROTOCOL.contains(&format!("### POST {PATH_RESULTS}\n")));
    assert!(PROTOCOL.contains(&format!("Base URL default `{DEFAULT_API_URL}`")));
}

#[test]
fn user_agent_format() {
    assert!(PROTOCOL.contains("`User-Agent: bynh-status-agent/<version> (<os>; <arch>)`"));
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
