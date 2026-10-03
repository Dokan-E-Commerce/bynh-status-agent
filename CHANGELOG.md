# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

## [1.2.0] – not yet released

### Added

- Round robin (protocol v1, additive; see “Round robin” in `PROTOCOL.md`): a check with a `schedule`
  runs at the wall-clock times `t` where `(t − epoch − phase_seconds) mod every_seconds == 0`, plus a
  fixed jitter of under 2 s from its id, so a monitor’s places take turns and it is checked once per
  interval in total. Without a `schedule` (an older platform) checks run every `interval_seconds` as
  before.
- Confirmation requests: the assignments’ `confirm` list asks the agent to run a check once, straight
  away; the result carries `confirm_nonce`. Each nonce runs once (remembered for 15 minutes), at most
  one confirmation per check every 10 s, requests for unassigned checks are ignored.
- Long-poll: when `hello` offers `long_poll_seconds`, assignment polls ask the platform to hold them
  (`?wait=N`, request timeout N + 15 s) and the agent polls again straight away after a change or a
  held answer, or after the poll interval when the platform answered at once. Polls run alongside
  result reports, so a held poll never delays them.

### Changed

- A check whose definition or schedule changes keeps its timer: the running timer picks up the change
  instead of restarting, never runs the same slot twice and never runs two scheduled checks less than
  half an interval apart. A check in flight is no longer cut off by an assignment change.
- Timers re-read the wall clock at least every minute, so a clock correction is picked up.
- “assignments updated” is logged only when checks were added, changed or removed.

## [1.1.0] – not yet released

### Added

- Check details on every result (protocol v1, additive; see “Check details” in `PROTOCOL.md`): HTTP
  version, IP family, the configured request method and URL, status text, ordered response headers,
  a body sample (first 64 KiB, base64 for binary content) with size, SHA-256 and content type,
  redirect hops (target, status, duration, address), TLS details (protocol, cipher, subject, issuer,
  SANs, validity, SHA-256 fingerprint, chain length, verification result and reason) and
  `download_ms`/`total_ms` timings. Failures include everything gathered up to the failing phase.
- The assignment field `capture_body` (default `true`) turns the body sample off per monitor.
- Body samples are only sent when useful: on failure, when the body changed since the last sample
  sent for the check, at least hourly, and on the first result after start. Otherwise the result
  says `"sample_omitted": "unchanged"`.
- `bynh-status-agent check` prints the details; `--no-body` leaves the body sample out.

### Security

- Response header values that can carry credentials (`set-cookie`, `authorization`, `cookie`,
  `www-authenticate`, and names containing `token`, `secret`, `key`, `session`, `auth`, `password`
  or `signature`) are redacted on the agent. Request headers and monitor credentials are never part
  of the details.

### Changed

- Each result stays within 128 KiB of JSON (the body sample is shortened first, then headers).
- The result buffer also has a 64 MiB byte budget: body samples of the oldest results go first,
  then the oldest results. Result batches are capped at 8 MiB.
- TLS checks read the certificate of an untrusted or expired server from the failed handshake
  instead of opening a second connection; checks with `verify_tls = false` still verify the chain
  and report the outcome in the details without failing.

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
- Assignment validation and limits, `deny_cidrs`, a cross-origin header allowlist on redirects,
  more reserved address ranges, and an opt-in (`insecure_api_url`) for a plain-http platform URL.
- Signed releases: build-provenance attestations for binaries, a cosign-signed image with SBOM and
  provenance, pinned actions, toolchain and base images, and `cargo deny` in CI.
- Multi-arch scratch container image, hardened systemd unit, installer, Docker Compose and
  Kubernetes examples.
