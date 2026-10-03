//! Outbound HTTP proxy settings: `proxy_url` / `no_proxy` from the config, or
//! the conventional `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and `NO_PROXY`
//! variables (lowercase variants first, as curl does).
//!
//! Only `http://` proxies are supported. HTTPS targets (and tcp/tls checks)
//! go through an HTTP `CONNECT` tunnel; plain-HTTP targets are sent to the
//! proxy in absolute form. Proxy credentials are never logged.

use std::fmt;
use std::net::IpAddr;

use base64::Engine as _;

/// One proxy server.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    /// Ready-made `Proxy-Authorization` value (`Basic …`), if the URL had
    /// credentials.
    pub authorization: Option<String>,
}

impl fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for ProxyEndpoint {
    /// `http://host:port`, plus a marker if credentials are set. Never the
    /// credentials themselves.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        write!(f, "http://{host}:{}", self.port)?;
        if self.authorization.is_some() {
            f.write_str(" (with credentials)")?;
        }
        Ok(())
    }
}

impl ProxyEndpoint {
    /// Parses `http://[user:pass@]host[:port]`; a bare `host:port` means http.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let with_scheme = if raw.contains("://") {
            raw.to_owned()
        } else {
            format!("http://{raw}")
        };
        let u = url::Url::parse(&with_scheme).map_err(|_| "invalid proxy URL".to_owned())?;
        if u.scheme() != "http" {
            return Err(format!(
                "unsupported proxy scheme {:?}; only http:// proxies are supported",
                u.scheme()
            ));
        }
        let host = match u.host() {
            Some(url::Host::Domain(d)) => d.to_owned(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            None => return Err("proxy URL has no host".to_owned()),
        };
        let port = u.port().unwrap_or(80);
        let authorization = if u.username().is_empty() {
            None
        } else {
            let user = percent_decode(u.username());
            let pass = percent_decode(u.password().unwrap_or(""));
            Some(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
            ))
        };
        Ok(Self {
            host,
            port,
            authorization,
        })
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    /// Matches the domain and its subdomains (`example.com`, `.example.com`).
    Domain(String),
    Ip(IpAddr),
    Cidr(crate::netguard::Cidr),
}

/// Hosts that bypass the proxy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoProxy {
    all: bool,
    rules: Vec<Rule>,
}

impl NoProxy {
    /// Comma- or space-separated list: `*`, domains (`example.com`,
    /// `.example.com`), IP addresses and CIDR ranges. Ports are ignored.
    pub fn parse(raw: &str) -> Self {
        let mut np = NoProxy::default();
        for item in raw
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if item == "*" {
                np.all = true;
                continue;
            }
            if item.contains('/') {
                if let Some(c) = crate::netguard::Cidr::parse(item) {
                    np.rules.push(Rule::Cidr(c));
                }
                continue;
            }
            let bare = item.trim_start_matches('[');
            let bare = match bare.split_once(']') {
                Some((v6, _)) => v6,
                None => bare,
            };
            if let Ok(ip) = bare.parse::<IpAddr>() {
                np.rules.push(Rule::Ip(ip));
                continue;
            }
            // strip a :port suffix from domain entries
            let domain = item.rsplit_once(':').map_or(item, |(d, _)| d);
            let domain = domain.trim_start_matches("*.").trim_start_matches('.');
            if !domain.is_empty() {
                np.rules.push(Rule::Domain(domain.to_ascii_lowercase()));
            }
        }
        np
    }

    /// True if `host` (a name or IP literal without brackets) bypasses the proxy.
    pub fn matches(&self, host: &str) -> bool {
        if self.all {
            return true;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let ip = host.parse::<IpAddr>().ok();
        self.rules.iter().any(|r| match (r, ip) {
            (Rule::Domain(d), None) => host == *d || host.ends_with(&format!(".{d}")),
            (Rule::Ip(a), Some(ip)) => *a == ip,
            (Rule::Cidr(c), Some(ip)) => c.contains(ip),
            _ => false,
        })
    }

    pub fn is_empty(&self) -> bool {
        !self.all && self.rules.is_empty()
    }
}

/// The resolved proxy configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxySettings {
    /// Used for `https://` targets and tcp/tls checks (CONNECT tunnel).
    pub https: Option<ProxyEndpoint>,
    /// Used for `http://` targets.
    pub http: Option<ProxyEndpoint>,
    pub no_proxy: NoProxy,
}

impl ProxySettings {
    /// `proxy_url` applies to every scheme. Without it, the standard
    /// environment variables are read. `no_proxy` falls back to
    /// `no_proxy`/`NO_PROXY`.
    pub fn resolve(
        proxy_url: Option<&str>,
        no_proxy: Option<&str>,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, String> {
        let first = |names: &[&str]| names.iter().find_map(|n| env(n));
        let parse =
            |name: &str, v: String| ProxyEndpoint::parse(&v).map_err(|e| format!("{name}: {e}"));
        let (https, http) = match proxy_url {
            Some(p) => {
                let ep = parse("proxy_url", p.to_owned())?;
                (Some(ep.clone()), Some(ep))
            }
            None => {
                let all = first(&["all_proxy", "ALL_PROXY"]);
                let https = first(&["https_proxy", "HTTPS_PROXY"]).or_else(|| all.clone());
                let http = first(&["http_proxy", "HTTP_PROXY"]).or(all);
                (
                    https.map(|v| parse("HTTPS_PROXY", v)).transpose()?,
                    http.map(|v| parse("HTTP_PROXY", v)).transpose()?,
                )
            }
        };
        let no_proxy = match no_proxy {
            Some(n) => NoProxy::parse(n),
            None => first(&["no_proxy", "NO_PROXY"])
                .map(|n| NoProxy::parse(&n))
                .unwrap_or_default(),
        };
        Ok(Self {
            https,
            http,
            no_proxy,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.https.is_none() && self.http.is_none()
    }

    /// The proxy for a connection to `host`, or `None` to connect directly.
    /// `tunnel` is true for https targets and tcp/tls checks.
    pub fn for_host(&self, host: &str, tunnel: bool) -> Option<&ProxyEndpoint> {
        let ep = if tunnel {
            self.https.as_ref()
        } else {
            self.http.as_ref()
        }?;
        if self.no_proxy.matches(host) {
            None
        } else {
            Some(ep)
        }
    }

    pub fn for_url(&self, url: &url::Url) -> Option<&ProxyEndpoint> {
        let host = crate::net::host_of(url).ok()?;
        self.for_host(&host, url.scheme() == "https")
    }

    /// One line for the startup log, without credentials.
    pub fn describe(&self) -> String {
        match (&self.https, &self.http) {
            (None, None) => "none".to_owned(),
            (Some(a), Some(b)) if a == b => a.to_string(),
            (a, b) => format!(
                "https: {}, http: {}",
                a.as_ref().map_or("none".into(), |e| e.to_string()),
                b.as_ref().map_or("none".into(), |e| e.to_string())
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parses_endpoints() {
        let p = ProxyEndpoint::parse("http://proxy.corp:3128").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("proxy.corp", 3128));
        assert!(p.authorization.is_none());
        let p = ProxyEndpoint::parse("10.0.0.5:8080").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("10.0.0.5", 8080));
        let p = ProxyEndpoint::parse("http://proxy").unwrap();
        assert_eq!(p.port, 80);
        let p = ProxyEndpoint::parse("http://[::1]:3128").unwrap();
        assert_eq!(p.host, "::1");
        assert!(ProxyEndpoint::parse("socks5://p:1080").is_err());
        assert!(ProxyEndpoint::parse("https://p:443").is_err());
    }

    #[test]
    fn credentials_never_displayed() {
        let p = ProxyEndpoint::parse("http://alice:s%40cret@proxy.corp:3128").unwrap();
        // alice:s@cret
        assert_eq!(p.authorization.as_deref(), Some("Basic YWxpY2U6c0BjcmV0"));
        for s in [format!("{p}"), format!("{p:?}")] {
            assert!(!s.contains("alice") && !s.contains("cret"), "{s}");
            assert!(s.contains("proxy.corp:3128"));
        }
    }

    #[test]
    fn no_proxy_matching() {
        let np = NoProxy::parse(
            "localhost, .internal.example, corp.local:8080,10.0.0.0/8, 192.168.1.5,[::1], fd00::/8",
        );
        assert!(np.matches("localhost"));
        assert!(np.matches("db.internal.example"));
        assert!(np.matches("internal.example"));
        assert!(!np.matches("notinternal.example"));
        assert!(np.matches("corp.local"));
        assert!(np.matches("10.20.30.40"));
        assert!(!np.matches("11.0.0.1"));
        assert!(np.matches("192.168.1.5"));
        assert!(!np.matches("192.168.1.6"));
        assert!(np.matches("::1"));
        assert!(np.matches("fd12::1"));
        assert!(!np.matches("example.com"));
        assert!(NoProxy::parse("*").matches("anything"));
        assert!(NoProxy::parse("").is_empty());
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn resolve_precedence() {
        let env = env_of(&[
            ("HTTPS_PROXY", "http://upper:1"),
            ("https_proxy", "http://lower:2"),
            ("HTTP_PROXY", "http://plain:3"),
            ("NO_PROXY", "localhost"),
        ]);
        let s = ProxySettings::resolve(None, None, &env).unwrap();
        assert_eq!(s.https.as_ref().unwrap().host, "lower");
        assert_eq!(s.http.as_ref().unwrap().host, "plain");
        assert!(s.no_proxy.matches("localhost"));

        // proxy_url wins for both schemes; explicit no_proxy wins too
        let s = ProxySettings::resolve(Some("http://cfg:9"), Some("example.com"), &env).unwrap();
        assert_eq!(s.https.as_ref().unwrap().host, "cfg");
        assert_eq!(s.http.as_ref().unwrap().host, "cfg");
        assert!(!s.no_proxy.matches("localhost"));

        // ALL_PROXY as a fallback
        let s =
            ProxySettings::resolve(None, None, &env_of(&[("ALL_PROXY", "http://all:4")])).unwrap();
        assert_eq!(s.https.as_ref().unwrap().host, "all");
        assert_eq!(s.http.as_ref().unwrap().host, "all");

        assert!(ProxySettings::resolve(None, None, &env_of(&[]))
            .unwrap()
            .is_empty());
        assert!(
            ProxySettings::resolve(None, None, &env_of(&[("HTTPS_PROXY", "socks5://x:1")]))
                .is_err()
        );
    }

    #[test]
    fn picks_proxy_per_target() {
        let s = ProxySettings::resolve(
            None,
            Some("api.internal"),
            &env_of(&[
                ("HTTPS_PROXY", "http://tls:1"),
                ("HTTP_PROXY", "http://plain:2"),
            ]),
        )
        .unwrap();
        let u = |s: &str| url::Url::parse(s).unwrap();
        assert_eq!(s.for_url(&u("https://api.bynh.io/x")).unwrap().host, "tls");
        assert_eq!(s.for_url(&u("http://example.com/")).unwrap().host, "plain");
        assert!(s.for_url(&u("https://api.internal/")).is_none());
        assert_eq!(s.for_host("db.example", true).unwrap().host, "tls");
        assert_eq!(s.describe(), "https: http://tls:1, http: http://plain:2");
    }
}
