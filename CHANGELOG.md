# Changelog

All notable changes to `antsilk` are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-19

First public release. Two-line install, zero runtime dependencies.

### Added

- `AntsilkMiddleware` — ASGI middleware that wraps any FastAPI / Starlette /
  Litestar app with one `app.add_middleware(AntsilkMiddleware)` call.
- **Threat-intel rule** — proactive IP blocklist sourced from FireHOL Level 1
  and Spamhaus DROP. Stdlib-only fetch, tolerant CIDR parser, bisect lookup,
  background refresh every 6h. Refresh failures keep the previous in-memory
  set instead of crashing requests.
- **Rate limit rule** — async-safe per-IP token bucket. Default 60 req/min,
  tunable via `AntsilkConfig.requests_per_minute`.
- **Pattern scan rule** — compiled regex set covering SQL injection, XSS, and
  path traversal across URL path, query string, and non-`User-Agent` header
  values. Bodies are never read (deferred to v0.3.0 with proper buffering).
- **Header rule** — rejects requests with no User-Agent, known scanner UAs
  (`sqlmap`, `nikto`, `masscan`, `nmap`), and malformed `Cookie` headers.
- `AntsilkConfig` dataclass — single configuration object for thresholds,
  feeds, refresh cadence, and rule toggles.
- `RouteRule` dataclass — per-route overrides via `fnmatchcase` globs:
  `skip_rate_limit`, `skip_pattern_scan`, `skip_body_scan`,
  `skip_threat_intel`. First-match wins.
- **Pluggable sinks** — `EventSink` protocol with three built-ins:
  - `SQLiteSink` (default; WAL mode, hybrid columns + JSON `event_data`)
  - `JSONLinesSink` (append-only ledger to disk)
  - `RemoteSink` (stub; raises `NotImplementedError` until v0.5.0)
- `Event` dataclass — structured record for every block.
- `AntsilkBlocked` and `AntsilkRateLimited` exceptions exported for adopters
  who want to catch them in custom handlers.

### Performance

- < 1 ms p99 added latency per request on a typical FastAPI route.
- Zero runtime dependencies (stdlib only).

### Documentation

- MkDocs site at `docs.antsilk.com` covering quickstart, configuration,
  rules, and per-route overrides.
- Landing page at `https://antsilk.com`.

[0.1.0]: https://github.com/brianchenhao/antsilk/releases/tag/v0.1.0
