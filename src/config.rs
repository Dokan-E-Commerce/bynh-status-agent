//! Agent configuration: a TOML file and/or `BYNH_*` environment variables.
//! Environment variables override the file; no file is needed at all.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const DEFAULT_API_URL: &str = "https://api.bynh.io";
pub const DEFAULT_CONCURRENCY: usize = 64;
pub const MAX_CONCURRENCY: usize = 4096;
/// Name of the systemd credential holding the token (see `deploy/systemd`).
pub const SYSTEMD_CREDENTIAL: &str = "bynh-token";

/// Default config locations, tried in order when `--config` is not given.
pub fn default_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/bynh-status-agent/bynh-status-agent.toml"),
        PathBuf::from("bynh-status-agent.toml"),
    ]
}

#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub token: Option<String>,
    pub api_url: String,
    pub allow_private: bool,
    pub report_ip: bool,
    pub send_hostname: bool,
    pub concurrency: usize,
    /// Log filter, e.g. `info` or `bynh_status_agent=debug`.
    pub log: String,
    pub log_format: LogFormat,
    /// Extra PEM roots for internal certificate authorities.
    pub ca_file: Option<PathBuf>,
    /// Where the settings came from (for the startup log line).
    pub source: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Human,
    Json,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("token", &self.token.as_ref().map(|t| redact_token(t)))
            .field("api_url", &self.api_url)
            .field("allow_private", &self.allow_private)
            .field("report_ip", &self.report_ip)
            .field("send_hostname", &self.send_hostname)
            .field("concurrency", &self.concurrency)
            .field("log", &self.log)
            .field("log_format", &self.log_format)
            .field("ca_file", &self.ca_file)
            .field("source", &self.source)
            .finish()
    }
}

/// `bynh_agt_…abcd`: enough to tell tokens apart, useless to an attacker.
pub fn redact_token(token: &str) -> String {
    let tail: String = token
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if token.chars().count() <= 8 {
        "<redacted>".to_owned()
    } else {
        format!("bynh_agt_…{tail}")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            token: None,
            api_url: DEFAULT_API_URL.to_owned(),
            allow_private: false,
            report_ip: true,
            send_hostname: true,
            concurrency: DEFAULT_CONCURRENCY,
            log: "info".to_owned(),
            log_format: LogFormat::Human,
            ca_file: None,
            source: None,
        }
    }
}

/// The file format. Every key is optional.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    token: Option<String>,
    token_file: Option<PathBuf>,
    api_url: Option<String>,
    allow_private: Option<bool>,
    report_ip: Option<bool>,
    send_hostname: Option<bool>,
    concurrency: Option<usize>,
    log: Option<String>,
    log_format: Option<LogFormat>,
    ca_file: Option<PathBuf>,
}

#[derive(Debug)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn err(msg: impl Into<String>) -> ConfigError {
    ConfigError(msg.into())
}

fn parse_bool(name: &str, v: &str) -> Result<bool, ConfigError> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(err(format!("{name}: expected true or false, got {v:?}"))),
    }
}

fn read_token_file(path: &Path) -> Result<String, ConfigError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| err(format!("token_file {}: {e}", path.display())))?;
    let t = raw.trim().to_owned();
    if t.is_empty() {
        return Err(err(format!("token_file {} is empty", path.display())));
    }
    Ok(t)
}

impl Config {
    /// Loads configuration. With `explicit` set the file must exist; otherwise
    /// the first existing file in `defaults` is used, and none is fine.
    /// `env` looks up an environment variable (injected for tests).
    pub fn load(
        explicit: Option<&Path>,
        defaults: &[PathBuf],
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let path = match explicit {
            Some(p) => Some(p.to_path_buf()),
            None => defaults.iter().find(|p| p.is_file()).cloned(),
        };
        let file: FileConfig = match &path {
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .map_err(|e| err(format!("config {}: {e}", p.display())))?;
                toml::from_str(&text).map_err(|e| err(format!("config {}: {e}", p.display())))?
            }
            None => FileConfig::default(),
        };
        let env = |k: &str| env(k).filter(|v| !v.trim().is_empty());

        let mut c = Config {
            source: path,
            ..Config::default()
        };

        // token: BYNH_TOKEN > BYNH_TOKEN_FILE > file token > file token_file
        //        > $CREDENTIALS_DIRECTORY/bynh-token
        c.token = if let Some(t) = env("BYNH_TOKEN") {
            Some(t.trim().to_owned())
        } else if let Some(p) = env("BYNH_TOKEN_FILE") {
            Some(read_token_file(Path::new(p.trim()))?)
        } else if let Some(t) = file.token.filter(|t| !t.trim().is_empty()) {
            Some(t.trim().to_owned())
        } else if let Some(p) = file.token_file {
            Some(read_token_file(&p)?)
        } else if let Some(dir) = env("CREDENTIALS_DIRECTORY") {
            // systemd LoadCredential=bynh-token:/etc/bynh-status-agent/token
            let p = Path::new(&dir).join(SYSTEMD_CREDENTIAL);
            if p.is_file() {
                Some(read_token_file(&p)?)
            } else {
                None
            }
        } else {
            None
        };

        if let Some(v) = env("BYNH_API_URL").or(file.api_url) {
            c.api_url = v;
        }
        c.allow_private = match env("BYNH_ALLOW_PRIVATE") {
            Some(v) => parse_bool("BYNH_ALLOW_PRIVATE", &v)?,
            None => file.allow_private.unwrap_or(c.allow_private),
        };
        c.report_ip = match env("BYNH_REPORT_IP") {
            Some(v) => parse_bool("BYNH_REPORT_IP", &v)?,
            None => file.report_ip.unwrap_or(c.report_ip),
        };
        c.send_hostname = match env("BYNH_SEND_HOSTNAME") {
            Some(v) => parse_bool("BYNH_SEND_HOSTNAME", &v)?,
            None => file.send_hostname.unwrap_or(c.send_hostname),
        };
        c.concurrency = match env("BYNH_CONCURRENCY") {
            Some(v) => v
                .trim()
                .parse()
                .map_err(|_| err(format!("BYNH_CONCURRENCY: expected a number, got {v:?}")))?,
            None => file.concurrency.unwrap_or(c.concurrency),
        };
        if c.concurrency == 0 || c.concurrency > MAX_CONCURRENCY {
            return Err(err(format!(
                "concurrency must be between 1 and {MAX_CONCURRENCY}"
            )));
        }
        if let Some(v) = env("BYNH_LOG").or(file.log) {
            c.log = v;
        }
        c.log_format = match env("BYNH_LOG_FORMAT") {
            Some(v) => match v.trim().to_ascii_lowercase().as_str() {
                "human" | "text" => LogFormat::Human,
                "json" => LogFormat::Json,
                _ => {
                    return Err(err(format!(
                        "BYNH_LOG_FORMAT: expected human or json, got {v:?}"
                    )))
                }
            },
            None => file.log_format.unwrap_or_default(),
        };
        c.ca_file = env("BYNH_CA_FILE").map(PathBuf::from).or(file.ca_file);

        c.api_url = normalize_api_url(&c.api_url)?;
        Ok(c)
    }

    /// The token, or a helpful error if none is configured.
    pub fn require_token(&self) -> Result<&str, ConfigError> {
        let t = self.token.as_deref().ok_or_else(|| {
            err("no agent token: set BYNH_TOKEN (or token in bynh-status-agent.toml). Create one in bynh under Settings → Agents.")
        })?;
        if !t.starts_with("bynh_agt_") {
            return Err(err("the agent token should start with bynh_agt_; check that you copied the whole token"));
        }
        if t.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(err("the agent token contains whitespace"));
        }
        Ok(t)
    }
}

fn normalize_api_url(raw: &str) -> Result<String, ConfigError> {
    let u = url::Url::parse(raw.trim()).map_err(|e| err(format!("api_url {raw:?}: {e}")))?;
    match u.scheme() {
        "https" => {}
        "http" => {
            let local = match u.host() {
                Some(url::Host::Domain(d)) => d == "localhost",
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                None => false,
            };
            if !local {
                tracing::warn!("api_url uses plain http; the agent token will travel unencrypted");
            }
        }
        s => return Err(err(format!("api_url: unsupported scheme {s:?}"))),
    }
    if u.query().is_some() || u.fragment().is_some() || !u.username().is_empty() {
        return Err(err(
            "api_url must not contain credentials, a query or a fragment",
        ));
    }
    Ok(u.as_str().trim_end_matches('/').to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Write;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    fn file(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

    #[test]
    fn defaults_without_file_or_env() {
        let c = Config::load(None, &[], &env_of(&[])).unwrap();
        assert_eq!(c.api_url, DEFAULT_API_URL);
        assert!(!c.allow_private && c.report_ip && c.send_hostname);
        assert_eq!(c.concurrency, 64);
        assert!(c.token.is_none());
        assert!(c.require_token().is_err());
    }

    #[test]
    fn env_overrides_file() {
        let f = file(
            r#"
            token = "bynh_agt_file_token"
            api_url = "https://file.example/"
            allow_private = true
            report_ip = false
            concurrency = 8
            log = "debug"
        "#,
        );
        let c = Config::load(Some(f.path()), &[], &env_of(&[])).unwrap();
        assert_eq!(c.token.as_deref(), Some("bynh_agt_file_token"));
        assert_eq!(c.api_url, "https://file.example");
        assert!(c.allow_private && !c.report_ip);
        assert_eq!(c.concurrency, 8);
        assert_eq!(c.log, "debug");

        let c = Config::load(
            Some(f.path()),
            &[],
            &env_of(&[
                ("BYNH_TOKEN", "bynh_agt_env_token"),
                ("BYNH_API_URL", "http://127.0.0.1:9999"),
                ("BYNH_ALLOW_PRIVATE", "false"),
                ("BYNH_REPORT_IP", "yes"),
                ("BYNH_CONCURRENCY", "16"),
                ("BYNH_LOG", "warn"),
                ("BYNH_LOG_FORMAT", "json"),
            ]),
        )
        .unwrap();
        assert_eq!(c.token.as_deref(), Some("bynh_agt_env_token"));
        assert_eq!(c.api_url, "http://127.0.0.1:9999");
        assert!(!c.allow_private && c.report_ip);
        assert_eq!(c.concurrency, 16);
        assert_eq!(c.log, "warn");
        assert_eq!(c.log_format, LogFormat::Json);
    }

    #[test]
    fn empty_env_values_are_ignored() {
        let f = file("token = \"bynh_agt_file_token\"\n");
        let c = Config::load(Some(f.path()), &[], &env_of(&[("BYNH_TOKEN", "  ")])).unwrap();
        assert_eq!(c.token.as_deref(), Some("bynh_agt_file_token"));
    }

    #[test]
    fn token_file_precedence() {
        let tf = file("bynh_agt_from_file_xxxx\n");
        let tp = tf.path().to_str().unwrap();
        let cfg = file("token = \"bynh_agt_inline\"\n");
        // BYNH_TOKEN_FILE beats the file's inline token
        let c = Config::load(Some(cfg.path()), &[], &env_of(&[("BYNH_TOKEN_FILE", tp)])).unwrap();
        assert_eq!(c.token.as_deref(), Some("bynh_agt_from_file_xxxx"));
        // BYNH_TOKEN beats BYNH_TOKEN_FILE
        let c = Config::load(
            Some(cfg.path()),
            &[],
            &env_of(&[("BYNH_TOKEN_FILE", tp), ("BYNH_TOKEN", "bynh_agt_env")]),
        )
        .unwrap();
        assert_eq!(c.token.as_deref(), Some("bynh_agt_env"));
        // token_file key in the TOML file
        let cfg = file(&format!("token_file = {tp:?}\n"));
        let c = Config::load(Some(cfg.path()), &[], &env_of(&[])).unwrap();
        assert_eq!(c.token.as_deref(), Some("bynh_agt_from_file_xxxx"));
    }

    #[test]
    fn systemd_credential_is_the_last_resort() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SYSTEMD_CREDENTIAL),
            "bynh_agt_from_systemd\n",
        )
        .unwrap();
        let d = dir.path().to_str().unwrap();
        let c = Config::load(None, &[], &env_of(&[("CREDENTIALS_DIRECTORY", d)])).unwrap();
        assert_eq!(c.token.as_deref(), Some("bynh_agt_from_systemd"));
        let c = Config::load(
            None,
            &[],
            &env_of(&[("CREDENTIALS_DIRECTORY", d), ("BYNH_TOKEN", "bynh_agt_env")]),
        )
        .unwrap();
        assert_eq!(c.token.as_deref(), Some("bynh_agt_env"));
    }

    #[test]
    fn default_paths_in_order() {
        let a = file("concurrency = 1\n");
        let b = file("concurrency = 2\n");
        let missing = PathBuf::from("/definitely/not/here.toml");
        let c = Config::load(
            None,
            &[missing.clone(), a.path().into(), b.path().into()],
            &env_of(&[]),
        )
        .unwrap();
        assert_eq!(c.concurrency, 1);
        assert_eq!(c.source.as_deref(), Some(a.path()));
        // an explicit path must exist
        assert!(Config::load(Some(&missing), &[], &env_of(&[])).is_err());
    }

    #[test]
    fn rejects_bad_values() {
        assert!(Config::load(None, &[], &env_of(&[("BYNH_ALLOW_PRIVATE", "maybe")])).is_err());
        assert!(Config::load(None, &[], &env_of(&[("BYNH_CONCURRENCY", "0")])).is_err());
        assert!(Config::load(None, &[], &env_of(&[("BYNH_API_URL", "ftp://x")])).is_err());
        let f = file("tokn = \"typo\"\n");
        assert!(Config::load(Some(f.path()), &[], &env_of(&[])).is_err());
    }

    #[test]
    fn token_validation_and_redaction() {
        let c = Config {
            token: Some("bynh_agt_01H_abcdefghijklmnopqrstuvwxyz0123456789ABCD".into()),
            ..Config::default()
        };
        assert!(c.require_token().is_ok());
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("abcdefgh"), "{dbg}");
        assert!(dbg.contains("ABCD"));
        let c = Config {
            token: Some("nope".into()),
            ..Config::default()
        };
        assert!(c.require_token().is_err());
    }
}
