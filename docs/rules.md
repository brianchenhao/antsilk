# Rules

Antsilk runs four rule layers on every HTTP request. Each is described
here with the exact match criteria, response, and event shape.

## Layer order

Layers run in this fixed order. The first match short-circuits — only
one event is written per blocked request.

1. **threat-intel** (IP blocklist) — cheapest, rejects hostile IPs before any
   other work
2. **rate limit** (per-IP token bucket)
3. **headers** (structural sanity)
4. **patterns** (SQLi, XSS, path traversal regex)

Order is intentional: regex is the most expensive layer, so anything
that can reject sooner does.

## `threat_intel`

Drops traffic from IPs known to be hostile, based on plaintext CIDR
feeds.

| Property | Value |
|---|---|
| `rule_triggered` | `threat_intel` |
| `severity` | `high` |
| Response | `403 {"error": "blocked"}` |
| Default feeds | FireHOL Level 1, Spamhaus DROP |
| Refresh | Background task, every 6h |
| Skip flag | `RouteRule.skip_threat_intel` |

Refresh is fail-stale: if every feed errors, the previous in-memory set
is kept and a warning is logged. If the very first fetch fails, the
middleware boots with an empty set rather than crashing.

`event_data` includes the configured feed URLs:

```json
{"feeds": ["https://iplists.firehol.org/files/firehol_level1.netset", "https://www.spamhaus.org/drop/drop.txt"]}
```

## `rate_limit`

Per-IP token bucket. Capacity = `requests_per_minute`, refill rate =
`requests_per_minute / 60` tokens/sec.

| Property | Value |
|---|---|
| `rule_triggered` | `rate_limit` |
| `severity` | `low` |
| Response | `429 {"error": "rate_limited"}` with `Retry-After: 60` |
| Default budget | 60 req/min per IP |
| Skip flag | `RouteRule.skip_rate_limit` |

`event_data` includes the configured budget:

```json
{"requests_per_minute": 60}
```

Buckets are in-process. Multiple workers behind a load balancer get
per-worker limits, not per-cluster.

## `bad_header`

Three structural signals fire here. Header *content* (SQLi/XSS) is the
pattern scanner's job, not this layer's.

| Property | Value |
|---|---|
| `rule_triggered` | `bad_header` |
| `severity` | `medium` |
| Response | `403 {"error": "blocked"}` |
| Skip flag | (none — see below) |

Sub-rules, in evaluation order:

| `event_data.subrule` | When it fires |
|---|---|
| `missing_user_agent` | No `User-Agent` header, or value is empty / whitespace-only |
| `bad_user_agent`     | `sqlmap`, `nikto`, `masscan`, or `nmap` as a word in the UA |
| `malformed_cookie`   | `Cookie` header present but empty, missing `=`, or non-printable bytes |

There is no `skip_bad_header` flag. Bypassing missing-UA detection is
almost never what an adopter wants — every legitimate webhook source
sends a real User-Agent, and the bad-UA list is a closed set of
well-known attack tools.

## `sqli` / `xss` / `path_traversal`

Three regex-based content rules under one layer ("pattern scanner").
Each `rule_triggered` value is recorded separately so adopters can
filter on it later.

| Property | Value |
|---|---|
| `rule_triggered` | `sqli`, `xss`, or `path_traversal` |
| `severity` | `high` |
| Response | `403 {"error": "blocked"}` |
| Skip flag | `RouteRule.skip_pattern_scan` |

**Match locations** — every layer scans:

- The URL path itself
- The raw query string
- Every parsed query parameter value
- Every header value **except** `User-Agent` (UA is the headers rule's
  job — legitimate browsers send weird UAs)

**Match locations — explicitly not scanned in v0.1.0:**

- The request body. Body scanning consumes the ASGI receive stream and
  breaks downstream handlers. Deferred to v0.3.0 with proper buffering.
  `RouteRule.skip_body_scan` exists today as a no-op so configs survive
  the upgrade.

**Patterns:**

| Rule | Regex (case-insensitive) |
|---|---|
| `sqli` | `\b(union\s+select\|or\s+1\s*=\s*1\|--\s\|/\*.*\*/\|xp_cmdshell)\b` |
| `xss` | `<script[^>]*>\|javascript:\|on(load\|error\|click)\s*=` |
| `path_traversal` | `\.\./\|\.\.%2f\|%2e%2e/` |

`event_data` includes the matched substring (useful for forensics):

```json
{"matched": "or 1=1"}
```

The matched substring is **not** echoed in the HTTP response body — the
client sees only `{"error": "blocked"}` so a probe can't use Antsilk
itself to confirm a payload triggered.

## OWASP Top-10 coverage

Mapping the v0.1.0 rule set to the 2021 OWASP Top-10. Adopters reading
for "is this enough for SOC-2 / compliance / etc." should treat this
as a starting point, not a complete control.

| OWASP category                     | Rule(s) that cover it     |
| ---------------------------------- | ------------------------- |
| A01:2021 — Broken Access Control   | Partial (`path_traversal`) |
| A03:2021 — Injection               | `sqli`, `xss`             |
| A05:2021 — Security Misconfiguration | `bad_header`            |
| A06:2021 — Vulnerable Components   | Indirect (`threat_intel` catches scanners probing for CVEs) |
| A07:2021 — Identification/Auth Failures | Reserved (`bad_token` slot, v0.2.0+) |
| A09:2021 — Security Logging Failures | The event sink itself — every block is recorded |
| A10:2021 — SSRF                    | Out of scope                |

## Event schema

Every block (and only blocks — passes are not logged) writes one row to
the configured sink:

| Column            | Type    | Description |
|-------------------|---------|-------------|
| `id`              | int     | Auto-increment primary key |
| `timestamp`       | text    | ISO 8601 UTC, e.g. `2026-05-15T11:42:00.123456+00:00` |
| `ip_address`      | text    | Source IP, or `unknown` when the scope has none |
| `method`          | text    | HTTP method |
| `path`            | text    | Request path |
| `rule_triggered`  | text    | `threat_intel` / `rate_limit` / `bad_header` / `sqli` / `xss` / `path_traversal` |
| `severity`        | text    | `low` / `medium` / `high` |
| `response_code`   | integer | `403` or `429` |
| `user_agent`      | text    | Raw UA string, may be `NULL` |
| `app_id`          | text    | Optional adopter-set label for multi-app deployments |
| `event_data`      | text    | JSON blob, rule-specific detail |
