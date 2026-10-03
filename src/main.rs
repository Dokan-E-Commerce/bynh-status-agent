use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use bynh_status_agent::agent::{Agent, Tunables};
use bynh_status_agent::config::{default_paths, Config, LogFormat};
use bynh_status_agent::net::Net;
use bynh_status_agent::netguard::Guard;
use bynh_status_agent::probe::Prober;
use bynh_status_agent::protocol::{Check, CheckType, IpVersion, AGENT_VERSION};

#[derive(Parser)]
#[command(
    name = "bynh-status-agent",
    version,
    about = "Uptime monitoring agent for bynh. Runs checks assigned by the platform and reports the results."
)]
struct Cli {
    /// Config file (default: /etc/bynh-status-agent/bynh-status-agent.toml).
    /// Optional: every setting can come from BYNH_* environment variables.
    #[arg(long, global = true, env = "BYNH_CONFIG", value_name = "PATH")]
    config: Option<PathBuf>,

    /// Log format (overrides BYNH_LOG_FORMAT and the config file).
    #[arg(long, global = true, value_enum)]
    log_format: Option<LogFormat>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Connect to bynh and run assigned checks (the default).
    Run,
    /// Run one check locally and print the result, with its details, as JSON.
    /// Nothing is sent to bynh.
    Check(CheckArgs),
    /// Print the version.
    Version,
}

#[derive(Args)]
struct CheckArgs {
    /// URL for http/keyword/tls checks, host:port for tcp (and tls).
    target: String,
    /// Check type.
    #[arg(long = "type", value_enum, default_value_t = CliType::Http)]
    kind: CliType,
    /// HTTP method.
    #[arg(short = 'X', long, default_value = "GET")]
    method: String,
    /// Request header, "Name: value". Repeatable.
    #[arg(short = 'H', long = "header", value_name = "HEADER")]
    headers: Vec<String>,
    /// Request body.
    #[arg(long)]
    body: Option<String>,
    /// Keyword that must appear in the body (implies --type keyword).
    #[arg(long)]
    keyword: Option<String>,
    /// Fail when the keyword is present instead of absent.
    #[arg(long)]
    keyword_absent: bool,
    /// Expected status class or code, e.g. 2xx or 301. Repeatable. Default: 2xx.
    #[arg(long = "expect", value_name = "STATUS")]
    expected: Vec<String>,
    /// Timeout in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
    /// Don't follow redirects.
    #[arg(long)]
    no_follow: bool,
    /// Maximum redirects to follow.
    #[arg(long, default_value_t = 5)]
    max_redirects: u32,
    /// Don't verify TLS certificates.
    #[arg(long)]
    insecure: bool,
    /// IP version: any, 4 or 6.
    #[arg(long, default_value = "any", value_parser = ["any", "4", "6"])]
    ip_version: String,
    /// Allow private and internal addresses for this check.
    #[arg(long)]
    allow_private: bool,
    /// Leave the body sample out of the details (like `capture_body: false`).
    #[arg(long)]
    no_body: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum CliType {
    Http,
    Keyword,
    Tcp,
    Tls,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Command::Run);
    if let Command::Version = command {
        println!(
            "bynh-status-agent {AGENT_VERSION} ({}; {}) protocol {}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            bynh_status_agent::protocol::PROTOCOL_VERSION
        );
        return ExitCode::SUCCESS;
    }

    let env = |k: &str| std::env::var(k).ok();
    let mut config = match Config::load(cli.config.as_deref(), &default_paths(), &env) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bynh-status-agent: {e}");
            return ExitCode::from(2);
        }
    };
    if let Some(f) = cli.log_format {
        config.log_format = f;
    }
    // The secrets now live in `config`; keep them out of the environment that
    // child processes or crash tooling could see. Still single-threaded here.
    for key in ["BYNH_TOKEN", "BYNH_PROXY_URL"] {
        std::env::remove_var(key);
    }
    let fd_note = cap_concurrency_to_fd_limit(&mut config);

    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 8);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bynh-status-agent: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match command {
        Command::Check(args) => {
            // Logs go to stderr so stdout is just the JSON result.
            init_logging(&config, true);
            runtime.block_on(check_once(config, args))
        }
        _ => {
            init_logging(&config, false);
            if let Some(note) = fd_note {
                tracing::warn!("{note}");
            }
            runtime.block_on(run(config))
        }
    }
}

/// File descriptors kept free for DNS, the platform connection and logging.
const FD_RESERVE: u64 = 64;

/// Raises the soft open-file limit towards the hard limit (up to 65,536) and
/// lowers `concurrency` if the limit still can't cover it. Returns a note to
/// log once logging is up.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)] // rlim_t is u32 on some 32-bit targets
fn cap_concurrency_to_fd_limit(config: &mut Config) -> Option<String> {
    const WANT: u64 = 65_536;
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes into the struct we pass.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return None;
    }
    if lim.rlim_cur == libc::RLIM_INFINITY {
        return None;
    }
    let target = if lim.rlim_max == libc::RLIM_INFINITY {
        WANT
    } else {
        (lim.rlim_max as u64).min(WANT)
    };
    if (lim.rlim_cur as u64) < target {
        let raised = libc::rlimit {
            rlim_cur: target as libc::rlim_t,
            rlim_max: lim.rlim_max,
        };
        // SAFETY: setrlimit reads the struct we pass; failure is harmless.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            lim.rlim_cur = raised.rlim_cur;
        }
    }
    let budget = (lim.rlim_cur as u64).saturating_sub(FD_RESERVE).max(1);
    if (config.concurrency as u64) > budget {
        let note = format!(
            "concurrency {} exceeds the open-file limit ({}); using {budget}. Raise the limit (ulimit -n, LimitNOFILE) to run more checks at once.",
            config.concurrency, lim.rlim_cur
        );
        config.concurrency = budget as usize;
        return Some(note);
    }
    None
}

#[cfg(not(unix))]
fn cap_concurrency_to_fd_limit(_config: &mut Config) -> Option<String> {
    None
}

fn init_logging(config: &Config, to_stderr: bool) {
    let mut filter = if to_stderr && config.log == "info" {
        "warn".to_owned()
    } else {
        config.log.clone()
    };
    if !filter.contains("hickory") {
        filter.push_str(",hickory_proto=warn,hickory_net=warn,hickory_resolver=warn");
    }
    let filter = EnvFilter::try_new(&filter).unwrap_or_else(|e| {
        eprintln!(
            "bynh-status-agent: invalid log filter {:?} ({e}); using info",
            config.log
        );
        EnvFilter::new("info")
    });
    use std::io::IsTerminal;
    let ansi = std::env::var_os("NO_COLOR").is_none()
        && if to_stderr {
            std::io::stderr().is_terminal()
        } else {
            std::io::stdout().is_terminal()
        };
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(ansi)
        // If stdout and stderr are both gone (closed pipe), stay quiet
        // rather than abort while reporting the failed write.
        .log_internal_errors(false);
    match (config.log_format, to_stderr) {
        (LogFormat::Json, false) => builder
            .json()
            .flatten_event(true)
            .with_writer(std::io::stdout)
            .init(),
        (LogFormat::Json, true) => builder
            .json()
            .flatten_event(true)
            .with_writer(std::io::stderr)
            .init(),
        (LogFormat::Human, false) => builder.with_writer(std::io::stdout).init(),
        (LogFormat::Human, true) => builder.with_writer(std::io::stderr).init(),
    }
}

async fn run(config: Config) -> ExitCode {
    let agent = match Agent::new(config, Tunables::default()) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(2);
        }
    };
    let shutdown = CancellationToken::new();
    let trigger = shutdown.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutting down; flushing buffered results");
        trigger.cancel();
        // A second signal exits immediately.
        shutdown_signal().await;
        tracing::warn!("second signal; exiting without flushing");
        std::process::exit(130);
    });
    agent.run(shutdown).await;
    ExitCode::SUCCESS
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn check_once(config: Config, args: CheckArgs) -> ExitCode {
    let check = match build_check(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bynh-status-agent: {e}");
            return ExitCode::from(2);
        }
    };
    let net = match Net::new(config.ca_file.as_deref()) {
        Ok(n) => Arc::new(n),
        Err(e) => {
            eprintln!("bynh-status-agent: {e}");
            return ExitCode::from(2);
        }
    };
    let allow_private = config.allow_private || args.allow_private;
    let mut prober = Prober::new(
        net,
        Guard::new(allow_private).with_deny(config.deny_cidrs.clone()),
        true,
    );
    if config.check_via_proxy && allow_private {
        prober = prober.with_proxy(config.proxy.clone());
    }
    let result = prober.run(&check).await;
    match serde_json::to_string_pretty(&result) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("bynh-status-agent: {e}"),
    }
    if result.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn build_check(a: &CheckArgs) -> Result<Check, String> {
    let kind = match (a.kind, a.keyword.is_some()) {
        (CliType::Http, true) | (CliType::Keyword, _) => CheckType::Keyword,
        (CliType::Http, false) => CheckType::Http,
        (CliType::Tcp, _) => CheckType::Tcp,
        (CliType::Tls, _) => CheckType::Tls,
    };
    let mut c = Check::new("local", kind);
    let target = a.target.trim();
    match kind {
        CheckType::Http | CheckType::Keyword => {
            c.url = Some(if target.contains("://") {
                target.to_owned()
            } else {
                format!("https://{target}")
            });
        }
        CheckType::Tcp | CheckType::Tls => {
            if target.contains("://") {
                c.url = Some(target.to_owned());
            } else {
                let u = url::Url::parse(&format!("tcp://{target}"))
                    .map_err(|e| format!("invalid target {target:?}: {e}"))?;
                c.host = Some(
                    u.host_str()
                        .ok_or("target has no host")?
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .to_owned(),
                );
                c.port = u.port();
                if kind == CheckType::Tcp && c.port.is_none() {
                    return Err("tcp checks need host:port".into());
                }
            }
        }
    }
    c.method = a.method.clone();
    for h in &a.headers {
        let (k, v) = h
            .split_once(':')
            .ok_or_else(|| format!("header {h:?} should look like \"Name: value\""))?;
        c.headers.insert(k.trim().to_owned(), v.trim().to_owned());
    }
    c.body = a.body.clone();
    c.keyword = a.keyword.clone();
    c.keyword_absent = a.keyword_absent;
    c.expected_statuses = a.expected.clone();
    c.timeout_ms = a.timeout_ms;
    c.follow_redirects = !a.no_follow;
    c.max_redirects = a.max_redirects;
    c.verify_tls = !a.insecure;
    c.capture_body = !a.no_body;
    c.ip_version = match a.ip_version.as_str() {
        "4" => IpVersion::V4,
        "6" => IpVersion::V6,
        _ => IpVersion::Any,
    };
    c.validate().map_err(|e| format!("invalid check: {e}"))
}
