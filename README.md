# bynh-status-agent

The open-source monitoring agent for [bynh](https://bynh.io) status pages. It runs the HTTP, keyword,
TCP and TLS checks that bynh assigns to it and reports the results back. It is one small static
binary (about 4 MB, a 7 MB container image) that only ever makes outbound HTTPS requests, so it works
behind NAT, firewalls and on-premise networks.

- **Platform agents** are run by bynh in its regions. Any workspace can pick them per monitor.
- **Own agents** are created in your workspace (Settings → Agents) and run wherever you want: in your
  office, your VPC, next to an internal service. Only your workspace’s monitors are assigned to them,
  and they can check private addresses if you allow it.

The wire protocol is in [PROTOCOL.md](PROTOCOL.md).

---

## Run it anywhere

The agent needs three things:

1. **A token.** Create an agent in bynh under Settings → Agents and copy the token (`bynh_agt_…`). It is
   shown once.
2. **Outbound HTTPS** to `api.bynh.io:443`, plus whatever your checks need to reach. No inbound ports,
   no public IP.
3. **A long-running process.** The agent keeps its own timers. Hosts that only run a container for a
   request, or run it to completion, are not suitable (see [Hosts that won’t work](#hosts-that-wont-work)).

Everything is configured with environment variables; no config file is needed. Logs go to stdout.
The agent stops cleanly on `SIGTERM`, flushing buffered results first, and needs no writable file
system. Run **one instance per token**: two agents with the same token would run every check twice.

The image is `ghcr.io/dokan-e-commerce/bynh-status-agent` for `linux/amd64` and `linux/arm64`. Tags:
`1` (latest 1.x), `1.0`, `1.0.0`. It is built from scratch: the static binary, CA certificates, and
nothing else. It runs as UID/GID 65532.

To keep the token out of your shell history, read it into the environment first:

```sh
read -rs BYNH_TOKEN && export BYNH_TOKEN
```

### Docker

```sh
docker run -d --name bynh-status-agent --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e BYNH_TOKEN \
  ghcr.io/dokan-e-commerce/bynh-status-agent:1
```

`-e BYNH_TOKEN` without a value passes the variable from your shell, so the token never appears in
the command line. Follow the logs with `docker logs -f bynh-status-agent`.

### Docker Compose

[`deploy/docker-compose.yml`](deploy/docker-compose.yml) is ready to use. Put `BYNH_TOKEN=bynh_agt_…`
in a `.env` file next to it (and keep that file out of version control), then:

```sh
docker compose -f deploy/docker-compose.yml up -d
```

### Kubernetes

```sh
kubectl create namespace bynh
kubectl -n bynh create secret generic bynh-status-agent --from-literal=token="$BYNH_TOKEN"
kubectl -n bynh apply -f deploy/kubernetes/deployment.yaml
```

[`deploy/kubernetes/deployment.yaml`](deploy/kubernetes/deployment.yaml) runs one replica with a
read-only root file system, no privileges or capabilities, a 128 Mi memory limit and JSON logs. To
check in-cluster services, set `BYNH_ALLOW_PRIVATE=true` in the manifest.

### Podman

```sh
printf '%s' "$BYNH_TOKEN" | podman secret create bynh_token -
podman run -d --name bynh-status-agent --restart unless-stopped --read-only \
  --secret bynh_token,type=env,target=BYNH_TOKEN \
  ghcr.io/dokan-e-commerce/bynh-status-agent:1
```

Rootless Podman works as is. For a systemd-managed container, generate a Quadlet unit from the same
options.

### Docker Swarm

```sh
printf '%s' "$BYNH_TOKEN" | docker secret create bynh_token -
docker service create --name bynh-status-agent --replicas 1 --read-only \
  --secret bynh_token -e BYNH_TOKEN_FILE=/run/secrets/bynh_token \
  ghcr.io/dokan-e-commerce/bynh-status-agent:1
```

### Nomad

```hcl
job "bynh-status-agent" {
  group "agent" {
    count = 1
    task "agent" {
      driver = "docker"
      config {
        image           = "ghcr.io/dokan-e-commerce/bynh-status-agent:1"
        readonly_rootfs = true
      }
      template {
        # or {{ with nomadVar "nomad/jobs/bynh-status-agent" }}{{ .token }}{{ end }}
        data        = "BYNH_TOKEN={{ with secret \"kv/data/bynh\" }}{{ .Data.data.token }}{{ end }}"
        destination = "secrets/agent.env"
        env         = true
      }
      resources {
        cpu    = 100
        memory = 64
      }
    }
  }
}
```

### Fly.io

The agent serves nothing, so the app needs no services or public IPs. Without an `[http_service]`
section, Fly doesn’t stop the machine for being idle.

```sh
fly launch --image ghcr.io/dokan-e-commerce/bynh-status-agent:1 --no-deploy
# delete the [http_service] section from fly.toml
fly secrets set BYNH_TOKEN="$BYNH_TOKEN"
fly deploy --ha=false
```

### Railway

Create a service from the Docker image `ghcr.io/dokan-e-commerce/bynh-status-agent:1`, add the
variable `BYNH_TOKEN`, and leave public networking off. One replica.

### Render

Create a **Background Worker** (not a Web Service, which expects an open port) from the existing
image `ghcr.io/dokan-e-commerce/bynh-status-agent:1`, and add `BYNH_TOKEN` as a secret environment
variable.

### AWS ECS and Fargate

Store the token in Secrets Manager and run one task (service desired count 1). The relevant part of
the container definition:

```json
{
  "name": "bynh-status-agent",
  "image": "ghcr.io/dokan-e-commerce/bynh-status-agent:1",
  "user": "65532:65532",
  "readonlyRootFilesystem": true,
  "secrets": [{ "name": "BYNH_TOKEN", "valueFrom": "arn:aws:secretsmanager:…:secret:bynh-agent-token" }],
  "environment": [{ "name": "BYNH_LOG_FORMAT", "value": "json" }],
  "logConfiguration": { "logDriver": "awslogs", "options": { "awslogs-group": "/bynh/agent", "awslogs-region": "eu-central-1", "awslogs-stream-prefix": "agent" } }
}
```

0.25 vCPU and 512 MB, the smallest Fargate size, is far more than it needs. The task needs outbound
internet access (a public subnet with a public IP, or a NAT gateway). Azure Container Instances and
Google Compute Engine or GKE work the same way: one always-on container with the token as a secret.

### Hosts that won’t work

- **Google Cloud Run** (services and jobs). Services expect the container to answer HTTP on a port
  and can scale to zero; jobs run to completion. Use Compute Engine, GKE or another host above.
- **Function platforms** such as AWS Lambda, Cloud Functions, Vercel or Netlify functions. They run
  per request and freeze in between, so checks would not run on time.

### Linux binary with systemd

The installer downloads the right release for your CPU, verifies it against the release’s
`SHA256SUMS`, installs it to `/usr/local/bin`, stores the token in a root-only file and starts a
hardened systemd unit. It asks for the token without echoing it, or reads `BYNH_TOKEN`; it never
takes the token as an argument.

```sh
curl -fsSLO https://raw.githubusercontent.com/Dokan-E-Commerce/bynh-status-agent/main/install.sh
less install.sh   # read it first
sudo sh install.sh                     # add --allow-private for an on-premise agent
sudo sh install.sh --uninstall         # remove it again (--purge also removes /etc/bynh-status-agent)
```

Running it again upgrades the binary and keeps your token and settings. To install by hand, see
[`deploy/systemd/README`](deploy/systemd/README). The unit needs systemd 247 or newer.

### Plain binary

Download `bynh-status-agent-<target>` for your platform from the
[releases](https://github.com/Dokan-E-Commerce/bynh-status-agent/releases) (Linux x86_64 and
aarch64 static musl, macOS x86_64 and arm64, Windows x86_64), check it against `SHA256SUMS`, and run:

```sh
sha256sum -c SHA256SUMS --ignore-missing
chmod +x bynh-status-agent-x86_64-unknown-linux-musl
BYNH_TOKEN=… ./bynh-status-agent-x86_64-unknown-linux-musl
```

---

## Configuration

Settings come from environment variables and, optionally, a TOML file. Environment variables win.
The file is read from `--config <path>` (or `BYNH_CONFIG`), otherwise from
`/etc/bynh-status-agent/bynh-status-agent.toml`, then `./bynh-status-agent.toml`. None is required.

| File key | Environment | Default | What it does |
| --- | --- | --- | --- |
| `token` | `BYNH_TOKEN` | – | The agent token, `bynh_agt_…`. Required. |
| `token_file` | `BYNH_TOKEN_FILE` | – | Read the token from a file instead (Docker/Kubernetes secrets). |
| `api_url` | `BYNH_API_URL` | `https://api.bynh.io` | Platform URL. |
| `allow_private` | `BYNH_ALLOW_PRIVATE` | `false` | Allow checks of private and internal addresses. For own, on-premise agents. |
| `report_ip` | `BYNH_REPORT_IP` | `true` | Include the IP each check connected to in its result. |
| `send_hostname` | `BYNH_SEND_HOSTNAME` | `true` | Send this machine’s hostname in `hello`, so you can tell agents apart. |
| `concurrency` | `BYNH_CONCURRENCY` | `64` | Checks running at the same time (1–4096). |
| `log` | `BYNH_LOG` | `info` | Log level or filter, such as `debug` or `warn`. |
| `log_format` | `BYNH_LOG_FORMAT` | `human` | `human` or `json`. Also `--log-format`. |
| `ca_file` | `BYNH_CA_FILE` | – | Extra PEM root certificates, for internal certificate authorities. |

Token lookup order: `BYNH_TOKEN`, `BYNH_TOKEN_FILE`, `token`, `token_file`, then the systemd credential
`$CREDENTIALS_DIRECTORY/bynh-token`. Values such as `true`, `false`, `1`, `0`, `yes` and `no` are
accepted for switches. Unknown keys in the file are an error, so typos don’t pass silently.

```toml
# /etc/bynh-status-agent/bynh-status-agent.toml
api_url = "https://api.bynh.io"
allow_private = false
report_ip = true
concurrency = 64
```

How often to poll, how often to report and how big a batch may be come from the platform in the
`hello` response.

## Commands

```text
bynh-status-agent [--config PATH] [--log-format human|json] [run]   run the agent (the default)
bynh-status-agent check <target> [options]                           run one check locally, print JSON
bynh-status-agent version                                            print version and protocol
```

`check` is for debugging a monitor from the agent’s point of view. It sends nothing to bynh and exits
with status 0 if the check passed, 1 if it failed:

```sh
bynh-status-agent check https://shop.example.com/health --expect 2xx
bynh-status-agent check https://shop.example.com --keyword "Add to cart"
bynh-status-agent check --type tcp db.internal:5432 --allow-private
bynh-status-agent check --type tls example.com
bynh-status-agent check -X POST -H 'Content-Type: application/json' --body '{}' https://api.example.com/ping
```

Run `bynh-status-agent check --help` for every option.

## What the agent sends

Only what the protocol defines, to the `api_url` you configure:

- **`hello`** at start: agent version, OS, CPU architecture, the start time and, unless
  `send_hostname = false`, the hostname.
- **Assignment polls**: no body.
- **Check results**: check id, start time, duration, pass or fail, status code, error kind and a short
  message, phase timings, certificate expiry, bytes read, and the IP connected to (unless
  `report_ip = false`).

Response bodies, headers, and the credentials configured on your monitors are never sent anywhere
other than the monitored target. There is no telemetry, no crash reporting and no other destination.

## Security model

- **Outbound only.** The agent opens no ports. It connects to bynh over HTTPS and to the targets of
  its checks.
- **The token** is read from the environment, a file or a systemd credential. It is never accepted as
  a command-line argument by the installer, never logged (logs show `bynh_agt_…` and its last four
  characters) and only sent to `api_url`. Debug logs replace `Authorization`, `Cookie` and similar
  header values with `<redacted>`. Monitor credentials (basic and bearer auth) are never logged.
- **Private addresses are refused by default.** Unless `allow_private = true`, the agent will not
  connect to loopback (`127.0.0.0/8`, `::1`), private (`10/8`, `172.16/12`, `192.168/16`), link-local
  (`169.254/16`, `fe80::/10`), carrier-grade NAT (`100.64/10`), multicast, unspecified, reserved and
  benchmarking ranges, IPv6 unique local addresses (`fc00::/7`), cloud metadata endpoints
  (`169.254.169.254`, `fd00:ec2::254`), or any IPv6 address that embeds one of those IPv4 addresses
  (IPv4-mapped, IPv4-compatible, NAT64, 6to4). Such checks fail with the error kind `blocked`.
  Platform agents always run with this on; bynh never assigns private targets to them.
- **No DNS rebinding.** Each host name is resolved once, the address is checked against the rules
  above, and the connection goes to that exact address.
- **Every redirect is checked again.** Each hop is resolved and vetted the same way, so a public URL
  can’t redirect the agent into your network. Credentials (`Authorization`, `Cookie`) are dropped when
  a redirect leaves the original origin.
- **Bounded work.** At most 1 MiB of each response body is read. Checks time out (2 minutes at most),
  run under a concurrency limit, and the result buffer holds at most 10,000 results.
- **Least privilege when packaged.** The image is scratch-based, runs as UID 65532 and works with a
  read-only root file system. The systemd unit uses a dynamic user with no capabilities, a read-only
  system, restricted address families and system calls, and a 128 MB memory cap.
- **TLS** uses rustls with the Mozilla root store built in, so it doesn’t depend on the host’s
  certificate bundle. Add internal roots with `ca_file`. `verify_tls = false` on a monitor skips
  certificate validation for that monitor only.

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Allow-listing bynh’s checkers

If your firewall or WAF only lets known clients in, allow bynh’s platform checkers by IP. The current
list is published at:

- <https://api.bynh.io/api/v1/public/monitoring-ips> (JSON)
- <https://api.bynh.io/api/v1/public/monitoring-ips.txt> (one address or range per line)

Every request from an agent carries a stable User-Agent you can match on as well:

```text
bynh-status-agent/<version> (<os>; <arch>)
```

A monitor can override it with its own `User-Agent` header. Checks from your own agents come from the
machines you run them on, so allow those instead.

## How checks behave

- **http**: sends the request and compares the status with the monitor’s expected statuses (`2xx`,
  `3xx`, or exact codes such as `301`; none means any `2xx`). Redirects are followed up to the
  monitor’s limit, re-checking each hop; 301/302 after a `POST` and every 303 continue as `GET`.
- **keyword**: an http check that also requires a case-sensitive substring in the first 1 MiB of the
  body (or its absence, with `keyword_absent`).
- **tcp**: passes when a TCP connection to `host:port` opens.
- **tls**: completes a TLS handshake and reports the certificate’s expiry; it fails if the certificate
  is expired or, with `verify_tls`, not trusted. The expiry is reported even when validation fails.
  https http and keyword checks report `tls_expires_at` too.
- **Timings** are per phase, for the final request: `dns_ms` (0 for an IP address), `connect_ms`,
  `tls_ms`, and `ttfb_ms` (from sending the request to the response headers). Phases that didn’t
  happen are `null`. `duration_ms` covers the whole check, redirects included.
- **Scheduling**: every check runs every `interval_seconds` at a fixed offset derived from its id, so
  checks are spread out and keep their rhythm across restarts. When assignments change, untouched
  checks keep their timers.
- **IP version**: `any` prefers IPv4 when a host has both; `4` and `6` force one family.

## Resource use

Measured with 300 assigned checks (one-minute interval) on Linux, in the container image: about
3 MiB resident memory and no measurable CPU between checks. The release binary is about 4 MB.

## Building from source

You need a stable Rust toolchain ([rustup](https://rustup.rs)).

```sh
cargo build --release                 # target/release/bynh-status-agent
cargo test
cargo clippy --all-targets -- -D warnings
```

A static Linux binary:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl   # needs musl-tools (or use cargo-zigbuild)
```

The image, for both architectures:

```sh
docker buildx build --platform linux/amd64,linux/arm64 -t bynh-status-agent .
```

There is no C library to link against besides libc: TLS is rustls with the `ring` provider, DNS is
hickory-resolver, HTTP is hyper.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under the [Apache License 2.0](LICENSE).
