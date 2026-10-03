# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] – not yet released

First release, implementing the bynh agent protocol v1.

### Added

- HTTP, keyword, TCP and TLS (certificate expiry) checks with per-phase timings (DNS, connect, TLS,
  time to first byte), certificate expiry on https checks, redirects with a per-hop safety check,
  basic and bearer auth, custom methods, headers and bodies, and IPv4/IPv6 selection.
- Refusal of private, loopback, link-local, CGNAT, multicast, reserved, ULA and cloud metadata
  addresses (including IPv4-mapped and other embedded forms) unless `allow_private = true`.
- Scheduling with stable per-check offsets, a concurrency limit, and timers that survive assignment
  changes.
- Platform client with ETag polling, gzip result batches, a bounded 10,000-result buffer, backoff
  with jitter and `Retry-After`, and the protocol’s 401 and 426 handling.
- Configuration from environment variables and an optional TOML file; token from the environment, a
  file or a systemd credential.
- `bynh-status-agent check` for one-off local checks, JSON or human logs, graceful shutdown with a
  final flush.
- Outbound proxy support (`proxy_url`, `no_proxy`, or `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY`/`NO_PROXY`)
  for the platform connection, with `CONNECT` tunnels and basic proxy credentials; optional
  `check_via_proxy` for checks (requires `allow_private`).
- Multi-arch scratch container image, hardened systemd unit, installer, Docker Compose and
  Kubernetes examples.
