# Antsilk

**Drop-in security middleware for Python ASGI apps.**

Antsilk is a small, zero-dependency middleware that sits in front of your
FastAPI / Starlette / Litestar app and does the boring half of web
security for you. Two lines of glue and every incoming request gets
rate-limited, scanned for SQL injection / XSS / path traversal, checked
against an IP threat-intel blocklist, and inspected for suspicious
headers. Blocks are recorded as structured events in a local SQLite
ledger that you can query, ship to logs, or back with your own sink.

## Why it exists

Most ASGI apps end up reimplementing the same five checks: rate limit,
WAF-grade pattern scan, IP reputation, header sanity, and structured
logging. Each one is straightforward but the *combination* — wired into
one ordered middleware, sharing one event schema, with sensible defaults
— is what takes a weekend. Antsilk is that weekend, packaged up.

## What it does

| Layer            | What it catches                                                        | Response |
| ---------------- | ---------------------------------------------------------------------- | -------- |
| **threat-intel** | Traffic from IPs on FireHOL Level 1 or Spamhaus DROP                    | 403       |
| **rate limit**   | Per-IP token bucket; default 60 req/min                                | 429       |
| **headers**      | Missing User-Agent, `sqlmap`/`nikto`/`masscan`/`nmap`, malformed Cookie | 403       |
| **patterns**     | SQLi, XSS, path traversal regex over path / query / non-UA headers     | 403       |

Order matters: threat-intel is checked first because it's the cheapest
way to reject hostile traffic, before any regex runs. Patterns run last
because they're the most expensive.

## What it doesn't do

- **Body scanning.** Reading the request body in middleware consumes the
  ASGI receive stream and breaks the downstream handler. Body scanning
  is deferred to v0.3.0 with proper buffering. `skip_body_scan` already
  exists on `RouteRule` so your config survives the upgrade unchanged.
- **Auth.** The `bad_token` slot in the event schema is reserved for the
  identity gateway that lands in a later milestone. v0.1.0 is WAF + rate
  limit + telemetry only.
- **Cluster-wide rate limiting.** The token bucket is in-process. If you
  run multiple workers behind a load balancer you get per-worker limits,
  not per-cluster. Shared-state limiting needs Redis and is a v0.4.0
  conversation.

## Architecture in one diagram

```
                ┌─────────────────────────┐
                │   Internet / Users      │
                └──────────┬──────────────┘
                           │ HTTP request
                           ▼
              ┌─────────────────────────────────┐
              │   Adopter's FastAPI App         │
              │   ┌───────────────────────────┐ │
              │   │   AntsilkMiddleware       │ │
              │   │   ─ threat-intel          │ │
              │   │   ─ rate limiter          │ │
              │   │   ─ header sanity check   │ │
              │   │   ─ pattern scanner       │ │
              │   │   ─ event sink            │ │
              │   └─────────┬─────────────────┘ │
              │             │ pass / block      │
              │             ▼                   │
              │      Route Handlers             │
              └─────────────┬───────────────────┘
                            │ event sink
                ┌───────────┴────────────┐
                ▼                        ▼
         ┌─────────────┐         ┌──────────────────┐
         │  SQLite     │         │  JSONLinesSink   │
         │  events.db  │         │  (or your own)   │
         │  (default)  │         │                  │
         └─────────────┘         └──────────────────┘
```

## Get started

- **[Quickstart](quickstart.md)** — two-line install on a fresh FastAPI app
- **[Configuration](configuration.md)** — every knob on `AntsilkConfig`
- **[Rules](rules.md)** — what each layer matches, mapped to OWASP
- **[Per-route overrides](per-route-overrides.md)** — webhook + UGC carve-outs
