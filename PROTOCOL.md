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
