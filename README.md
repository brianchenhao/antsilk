# antsilk

[![tests](https://github.com/brianchenhao/antsilk/actions/workflows/test.yml/badge.svg)](https://github.com/brianchenhao/antsilk/actions/workflows/test.yml)
[![coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)](https://github.com/brianchenhao/antsilk/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/antsilk.svg)](https://pypi.org/project/antsilk/)
[![Python](https://img.shields.io/pypi/pyversions/antsilk.svg)](https://pypi.org/project/antsilk/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Drop-in security middleware for Python ASGI apps.**

`antsilk` is a small, zero-dependency middleware that sits in front of
your FastAPI / Starlette / Litestar app and does the boring half of web
security for you. Two lines of glue and every incoming request gets
rate-limited, scanned for SQL injection / XSS / path traversal, checked
against an IP threat-intel blocklist, and inspected for suspicious
headers. Blocks are recorded as structured events in a local SQLite
ledger.

## Install

```bash
pip install antsilk
```

## Two-line install

```python
from fastapi import FastAPI
from antsilk import AntsilkMiddleware

app = FastAPI()
app.add_middleware(AntsilkMiddleware)
```

Restart your server. Antsilk is now active with defaults:

- 60 requests per minute per IP
- threat-intel from FireHOL Level 1 + Spamhaus DROP, refreshed every 6h
- SQLi / XSS / path-traversal regex over URL, query, non-UA headers
- structural header check (missing UA, bad UA, malformed Cookie)
- events written to `./antsilk_events.db` (SQLite, WAL mode)

## What it catches

| Layer            | What it catches                                                         | Response |
| ---------------- | ----------------------------------------------------------------------- | -------- |
| **threat-intel** | Traffic from IPs on FireHOL Level 1 or Spamhaus DROP                     | 403       |
| **rate limit**   | Per-IP token bucket; default 60 req/min                                 | 429       |
| **headers**      | Missing User-Agent, `sqlmap`/`nikto`/`masscan`/`nmap`, malformed Cookie  | 403       |
| **patterns**     | SQLi, XSS, path traversal regex over path / query / non-UA headers      | 403       |

## Why

- **Zero runtime dependencies.** Standard library only. Every dep is
  friction for adopters and a supply-chain risk.
- **`< 1ms` p99 latency overhead** on a typical FastAPI route.
- **Sensible defaults.** Two-line install gives you a real WAF on day one.
- **Pluggable.** Swap `SQLiteSink` for `JSONLinesSink`, or write your own.
- **Carve-outs that match how apps actually look.** Webhooks bypass rate
  limit; user-content endpoints bypass pattern scan; payment endpoints
  bypass threat-intel — all wired through `RouteRule`.

## Docs

- [Quickstart](docs/quickstart.md)
- [Configuration](docs/configuration.md)
- [Rules](docs/rules.md)
- [Per-route overrides](docs/per-route-overrides.md)

Full docs site: `docs.antsilk.com` (coming online with the v0.1.0 launch).

## Status

`v0.1.0` — first published release. Public API frozen during the
`v0.1.x` line; breaking changes wait for `v0.2.0` after a deprecation
warning. Body scanning is deferred to `v0.3.0`.

## License

MIT
