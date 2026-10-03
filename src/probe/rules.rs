//! Pure decision rules used by the probes (easy to unit test).

use http::Method;

/// Keyword search window: only the first 1 MiB of a body is considered.
pub const KEYWORD_WINDOW: usize = 1 << 20;

/// True if `code` matches any of `expected` (`"2xx"`-style classes or exact
/// codes like `"301"`). Entries that are neither are ignored. An empty list,
/// or one with no valid entry, means "any 2xx".
pub fn status_matches(code: u16, expected: &[String]) -> bool {
    let mut any_valid = false;
    for raw in expected {
        let e = raw.trim();
        let b = e.as_bytes();
        if b.len() == 3
            && b[0].is_ascii_digit()
            && b[1].eq_ignore_ascii_case(&b'x')
            && b[2].eq_ignore_ascii_case(&b'x')
        {
            any_valid = true;
            if u16::from(b[0] - b'0') == code / 100 {
                return true;
            }
        } else if let Ok(exact) = e.parse::<u16>() {
            any_valid = true;
            if exact == code {
                return true;
            }
        }
    }
    !any_valid && (200..300).contains(&code)
}

/// Case-sensitive substring search over the first [`KEYWORD_WINDOW`] bytes.
pub fn keyword_found(body: &[u8], keyword: &str) -> bool {
    let window = &body[..body.len().min(KEYWORD_WINDOW)];
    memchr::memmem::find(window, keyword.as_bytes()).is_some()
}

pub fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Method for the next hop and whether the request body is kept, following
/// what browsers do: 303 always becomes GET (HEAD stays HEAD); 301/302 turn a
/// POST into a GET; 307/308 keep both method and body.
pub fn redirect_method(status: u16, method: &Method) -> (Method, bool) {
    match status {
        303 if *method != Method::HEAD => (Method::GET, false),
        301 | 302 if *method == Method::POST => (Method::GET, false),
        _ => (method.clone(), true),
    }
}

/// Headers kept when a redirect leaves the original origin. Everything else
/// configured on the monitor (credentials, API keys under any name) stays
/// with the origin it was meant for.
pub fn cross_origin_headers(headers: &http::HeaderMap, body_kept: bool) -> http::HeaderMap {
    use http::header;
    let mut out = http::HeaderMap::new();
    for (name, value) in headers {
        let keep = *name == header::USER_AGENT
            || *name == header::ACCEPT
            || *name == header::ACCEPT_LANGUAGE
            || *name == header::ACCEPT_ENCODING
            || (body_kept && *name == header::CONTENT_TYPE);
        if keep {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// Credentials are only sent to the origin they were configured for.
pub fn crosses_origin(from: &url::Url, to: &url::Url) -> bool {
    from.origin() != to.origin()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn status_classes_and_codes() {
        let e = v(&["2xx", "301", "4XX"]);
        assert!(status_matches(200, &e));
        assert!(status_matches(299, &e));
        assert!(status_matches(301, &e));
        assert!(!status_matches(302, &e));
        assert!(status_matches(404, &e));
        assert!(!status_matches(500, &e));
        assert!(!status_matches(199, &e));
    }

    #[test]
    fn status_defaults_to_2xx() {
        assert!(status_matches(204, &[]));
        assert!(!status_matches(301, &[]));
        assert!(!status_matches(500, &v(&["junk", ""])));
        assert!(status_matches(200, &v(&["junk"])));
        // one valid entry disables the default
        assert!(!status_matches(200, &v(&["junk", "3xx"])));
    }

    #[test]
    fn status_trims_whitespace() {
        assert!(status_matches(503, &v(&[" 503 "])));
        assert!(status_matches(503, &v(&[" 5xx"])));
    }

    #[test]
    fn keyword_is_case_sensitive() {
        assert!(keyword_found(b"status: OK", "OK"));
        assert!(!keyword_found(b"status: OK", "ok"));
        assert!(keyword_found("مرحبا بينه".as_bytes(), "بينه"));
    }

    #[test]
    fn keyword_only_in_first_mib() {
        let mut body = vec![b'a'; KEYWORD_WINDOW];
        body.extend_from_slice(b"needle");
        assert!(!keyword_found(&body, "needle"));
        // straddling the boundary does not count either
        let mut body = vec![b'a'; KEYWORD_WINDOW - 3];
        body.extend_from_slice(b"needle");
        assert!(!keyword_found(&body, "needle"));
        let mut body = vec![b'a'; KEYWORD_WINDOW - 6];
        body.extend_from_slice(b"needle");
        assert!(keyword_found(&body, "needle"));
    }

    #[test]
    fn redirect_methods() {
        assert_eq!(redirect_method(303, &Method::POST), (Method::GET, false));
        assert_eq!(redirect_method(303, &Method::HEAD), (Method::HEAD, true));
        assert_eq!(redirect_method(302, &Method::POST), (Method::GET, false));
        assert_eq!(redirect_method(301, &Method::PUT), (Method::PUT, true));
        assert_eq!(redirect_method(307, &Method::POST), (Method::POST, true));
        assert_eq!(
            redirect_method(308, &Method::DELETE),
            (Method::DELETE, true)
        );
        assert!(is_redirect(308) && !is_redirect(304) && !is_redirect(300));
    }

    #[test]
    fn cross_origin_keeps_only_safe_headers() {
        let mut h = http::HeaderMap::new();
        for (k, v) in [
            ("authorization", "Bearer t"),
            ("cookie", "c=1"),
            ("x-api-key", "secret"),
            ("user-agent", "ua"),
            ("accept", "*/*"),
            ("accept-language", "ar"),
            ("content-type", "application/json"),
        ] {
            h.insert(http::HeaderName::from_static(k), v.parse().unwrap());
        }
        let kept = cross_origin_headers(&h, false);
        let names: Vec<_> = kept.keys().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), 3, "{names:?}");
        assert!(kept.contains_key("user-agent") && kept.contains_key("accept-language"));
        assert!(!kept.contains_key("x-api-key") && !kept.contains_key("authorization"));
        assert!(cross_origin_headers(&h, true).contains_key("content-type"));
    }

    #[test]
    fn origins() {
        let a = url::Url::parse("https://a.example/x").unwrap();
        assert!(!crosses_origin(&a, &a.join("/y").unwrap()));
        assert!(crosses_origin(
            &a,
            &url::Url::parse("http://a.example/x").unwrap()
        ));
        assert!(crosses_origin(
            &a,
            &url::Url::parse("https://b.example/x").unwrap()
        ));
        assert!(crosses_origin(
            &a,
            &url::Url::parse("https://a.example:8443/").unwrap()
        ));
    }
}
