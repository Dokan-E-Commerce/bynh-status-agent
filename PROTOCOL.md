# bynh agent protocol, v1

The contract between a monitoring agent and the bynh platform. Both sides implement exactly this.
An agent only ever makes outbound HTTPS requests, so it works behind NAT and firewalls (on-premise).

## Agents
- **Platform agents**: run by bynh in its regions (Hetzner and others). `workspace_id` is null. Any workspace can pick them per monitor.
- **Own agents**: created by a workspace (Settings), run wherever the customer wants. Only that workspace's monitors are assigned to them.
  Own agents may check private/internal addresses (that's the point of on-premise). Platform agents never do: the platform never assigns a private target to them and the agent refuses private targets unless started with `allow_private = true`.

## Auth
- One token per agent, shown once at creation: `bynh_agt_<agent public id>_<secret>` (secret: 40 url-safe chars). The platform stores only a hash (sha256 of the whole token) and the last 4 chars.
- Every request: `Authorization: Bearer <token>`, `User-Agent: bynh-status-agent/<version> (<os>; <arch>)`, `X-Bynh-Agent-Protocol: 1`.
- 401 → token revoked or wrong: the agent stops checking, logs clearly, retries hello every 5 minutes.
- 426 → protocol/version too old: body `{ "message", "minimum_version" }`; the agent logs and keeps retrying hourly.
- 429/5xx → exponential backoff with jitter (1s → 5min cap), honour `Retry-After`.

Base URL default `https://api.bynh.io` (configurable, e.g. for self-test).

## Endpoints (all JSON, UTF-8; request bodies may be `Content-Encoding: gzip`)

### POST /api/v1/agent/hello
Request: `{ "version": "1.0.0", "os": "linux", "arch": "x86_64", "hostname": "probe-1" (optional, may be omitted for privacy), "started_at": RFC3339 }`
Response 200:
```json
{ "agent": { "id": "agt_01H…", "name": "Office probe", "kind": "own" | "platform", "region": "fsn1" | null, "location": "Falkenstein, DE" | null },
  "poll_interval_seconds": 30, "report_interval_seconds": 10, "max_batch": 500,
  "minimum_version": "1.0.0", "latest_version": "1.0.0" }
```
Called at start and after any 401 recovery. Also counts as a heartbeat.

### GET /api/v1/agent/assignments
Header `If-None-Match: "<config_version>"` → `304` when unchanged (also a heartbeat).
Response 200 with `ETag: "<config_version>"`:
```json
{ "config_version": "c_8f2…",
  "checks": [{
    "id": "mon_123",                 // stable id, echo back in results
    "type": "http" | "keyword" | "tcp" | "tls",   // tls = certificate expiry only
    "url": "https://shop.example.com/health",     // http/keyword/tls
    "host": "db.internal", "port": 5432,          // tcp (and tls when no url)
    "method": "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS",
    "headers": { "X-Probe": "1" },               // may be {}
    "body": null,                                  // string or null
    "auth": null | { "type": "basic", "username": "u", "password": "p" } | { "type": "bearer", "token": "t" },
    "timeout_ms": 10000,
    "interval_seconds": 60,
    "expected_statuses": ["2xx", "3xx", "401"],  // classes or exact codes
    "keyword": "ok" | null, "keyword_absent": false,  // keyword: case-sensitive substring of the body (first 1 MiB)
    "follow_redirects": true, "max_redirects": 5,
    "verify_tls": true,
    "ip_version": "any" | "4" | "6"
  }]
}
```
The agent schedules each check itself every `interval_seconds`, spreading start times with a stable per-check offset (hash of id) so checks don't burst. When assignments change, keep timers for unchanged checks.

### POST /api/v1/agent/results
Request `{ "results": [ … up to max_batch ] }`, each:
```json
{ "check_id": "mon_123", "started_at": "2026-10-03T05:00:00.123Z", "duration_ms": 182,
  "ok": true,
  "status_code": 200 | null,
  "error": null | { "kind": "dns" | "connect" | "timeout" | "tls" | "status" | "keyword" | "redirects" | "blocked" | "other", "message": "≤ 300 chars" },
  "timings": { "dns_ms": 5, "connect_ms": 20, "tls_ms": 40, "ttfb_ms": 150 } | null,
  "tls_expires_at": RFC3339 | null,
  "remote_ip": "203.0.113.5" | null,   // own agents may omit (privacy option `report_ip = false`)
  "response_bytes": 1234 | null }
```
Response `202 { "accepted": n, "rejected": [{ "index": i, "reason": "unknown_check" | "invalid" }] }`.
Results for checks no longer assigned are rejected (`unknown_check`), not an error.
The agent buffers unsent results in memory (bounded: 10,000; oldest dropped first, with a counter logged) and sends them when the platform is reachable again. Results are idempotent by (agent, check_id, started_at).

## Platform behaviour (for the backend)
- An agent is **online** if it polled in the last 3 × poll interval (90 s). Own agents going offline alert the workspace (in-app + email, once, and on recovery).
- A monitor runs from 1+ locations (platform regions and/or own agents) chosen by the workspace. The built-in checker (in the API cluster, Frankfurt) remains a location ("Frankfurt (built-in)") so nothing changes until agents exist.
- **Down decision**: a monitor is down when, within the last check window, failures come from at least `quorum` locations (default: majority of its locations that reported, minimum 1 when it has one location, 2 when it has 2+). One region failing alone is shown as "degraded in <location>" but opens no incident by default.
- Results go to ClickHouse `monitor_checks` with `location` (region code or agent id) through the existing pipeline.

## Configuration (agent)
Config file `bynh-status-agent.toml` (or env vars `BYNH_TOKEN`, `BYNH_API_URL`, `BYNH_ALLOW_PRIVATE`, `BYNH_REPORT_IP`, `BYNH_LOG`):
```toml
token = "bynh_agt_…"
api_url = "https://api.bynh.io"
allow_private = false   # true for on-premise agents checking internal hosts
report_ip = true
concurrency = 64
```

## Clarifications (v1)
Additive notes on behaviour the sections above leave open. They don't change the wire format; the reference agent (`bynh-status-agent`) behaves exactly like this.

1. **Timings.** Each field of `timings` is a number or `null`. A phase that didn't happen is `null`: `tls_ms` for plain HTTP and TCP checks, `ttfb_ms` for TCP and TLS checks. `dns_ms` is `0` when the target is an IP address. `timings` itself is `null` only when no phase completed. `ttfb_ms` runs from sending the request to receiving the response headers. When a check goes through an outbound proxy (`check_via_proxy`), `dns_ms` and `connect_ms` describe the connection to the proxy (tunnel setup included in `connect_ms`) and `remote_ip` is `null`.
2. **`response_bytes`.** The number of response body bytes the agent read, at most 1 MiB (1,048,576); the rest of a larger body is not read. `0` for `HEAD` and empty bodies, `null` for TCP and TLS checks.
3. **Redirects.** `status_code`, `timings`, `remote_ip` and `tls_expires_at` describe the final request (the one judged against `expected_statuses`). `duration_ms` covers the whole check, redirects included.
4. **Expected statuses.** An empty `expected_statuses`, or one with no valid entry, means any `2xx`. Entries are `Nxx` classes (case-insensitive) or exact codes; invalid entries are ignored.
5. **IP version.** With `ip_version: "any"`, a host that has both A and AAAA records is checked over IPv4.
6. **Bounds.** The agent clamps `interval_seconds` to 1–86,400 and `timeout_ms` to 1–120,000, and follows at most 20 redirects. It accepts at most 10,000 checks per assignment set (the rest are ignored) and assignment responses of at most 8 MiB (also after decompression). Per check: `id` ≤ 128 characters, `url` ≤ 8 KiB, ≤ 50 headers with values ≤ 8 KiB, `body` ≤ 64 KiB, `keyword` ≤ 1 KiB, `method` one of the values listed above, and `host` an IP address or a valid DNS name. A check outside these limits is skipped on its own.
7. **Unknown checks.** A check the agent can't parse (for example an unknown `type`) is skipped and logged; the rest of the assignment set still runs. No results are sent for it.
8. **Redirect rules.** Up to `max_redirects` redirects (301, 302, 303, 307, 308 with a `Location`) are followed; more is the error kind `redirects`. A 303 always continues as `GET` (a `HEAD` stays `HEAD`), and a 301 or 302 after a `POST` continues as `GET`; both drop the body. 307 and 308 keep the method and body. Each hop is resolved and checked against the private-address rules again, and `status_code` describes only the hop that answered last. User info in a `Location` is discarded. Once a redirect leaves the original origin (scheme, host and port), every header configured on the check, including `auth`, is dropped except `User-Agent`, `Accept`, `Accept-Language` and `Accept-Encoding` (and `Content-Type` while the body is kept). Checks can't set `Host`, `Content-Length`, `Transfer-Encoding`, `TE`, `Connection`, `Keep-Alive`, `Upgrade`, `Expect`, `Trailer` or `Proxy-*` headers; such entries are ignored.
9. **Refused result batches.** If `POST /results` answers with a 4xx other than 401, 426 or 429, the agent drops that batch (it would block every later result if retried) and logs it. 429 and 5xx keep the batch buffered for retry.
10. **Hostname.** `hello` includes `hostname` unless the agent is configured with `send_hostname = false`.

The reference agent is named `bynh-status-agent`: its User-Agent is `bynh-status-agent/<version> (<os>; <arch>)` and its config file is `bynh-status-agent.toml` (renamed from `bynh-agent` before the first release).
