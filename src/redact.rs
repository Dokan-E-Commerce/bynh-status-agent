//! Helpers that keep secrets out of logs.

use http::HeaderMap;

/// Headers whose values are never logged.
const SENSITIVE: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
];

/// A URL safe to log: user info and the query string are dropped.
pub fn url_for_log(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            if u.query().is_some() {
                u.set_query(Some("…"));
            }
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => "<unparseable url>".to_owned(),
    }
}

/// Renders headers for debug logs with sensitive values replaced.
pub fn headers_for_log(headers: &HeaderMap) -> String {
    let mut out = String::new();
    for (name, value) in headers {
        if !out.is_empty() {
            out.push_str(", ");
        }
        out.push_str(name.as_str());
        out.push_str(": ");
        if SENSITIVE.contains(&name.as_str()) {
            out.push_str("<redacted>");
        } else {
            out.push_str(value.to_str().unwrap_or("<binary>"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_authorization() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer bynh_agt_x_secret".parse().unwrap());
        h.insert("x-probe", "1".parse().unwrap());
        let s = headers_for_log(&h);
        assert!(!s.contains("secret"));
        assert!(s.contains("x-probe: 1"));
    }

    #[test]
    fn strips_userinfo_and_query() {
        let s = url_for_log("https://u:p@example.com/a?token=x#f");
        assert_eq!(s, "https://example.com/a?%E2%80%A6");
    }
}
