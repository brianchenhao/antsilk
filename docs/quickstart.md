# Quickstart

Two lines on a fresh FastAPI app and you're done.

## Install

```bash
pip install antsilk
```

`antsilk` has **zero runtime dependencies** — only the Python standard
library. The optional `[test]` extra pulls in pytest, httpx, and
FastAPI for the test suite; the optional `[docs]` extra pulls in
MkDocs Material for building this site.

## Add to your app

```python
from fastapi import FastAPI
from antsilk import AntsilkMiddleware

app = FastAPI()
app.add_middleware(AntsilkMiddleware)

@app.get("/")
async def root() -> dict[str, bool]:
    return {"ok": True}
```

Restart your server. Antsilk is now live with defaults:

- 60 requests per minute per IP
- threat-intel from FireHOL Level 1 + Spamhaus DROP, refreshed every 6h
- SQLi / XSS / path-traversal regex over URL, query, non-UA headers
- structural header check (missing UA, bad UA, malformed Cookie)
- events written to `./antsilk_events.db` (SQLite, WAL mode)

## Confirm it's running

In one terminal:

```bash
uvicorn main:app
```

In another:

```bash
# happy path
curl -s http://localhost:8000/        # → {"ok":true}

# SQLi → blocked
curl -s "http://localhost:8000/?id=1%20OR%201=1"
# → {"error":"blocked"}  (status 403)

# missing UA → blocked
curl -s -H "User-Agent:" http://localhost:8000/
# → {"error":"blocked"}  (status 403)
```

A file called `antsilk_events.db` appears in your working directory on
the first block. Inspect it with the `sqlite3` CLI:

```bash
sqlite3 antsilk_events.db "SELECT timestamp, ip_address, rule_triggered, response_code FROM events ORDER BY id DESC LIMIT 5"
```

## Recommended next steps

- If you have webhook callbacks or user-content endpoints, read
  **[Per-route overrides](per-route-overrides.md)** before deploying.
- If you want to swap SQLite for JSON Lines (or a custom sink), see
  the **[Configuration](configuration.md)** page.
- If you want to know exactly what each layer catches, see
  **[Rules](rules.md)**.

## Production checklist

1. Pick a place for `antsilk_events.db` that survives container restarts.
   Mount a persistent volume — the default path is the current working
   directory.
2. Set `requests_per_minute` honestly. The default 60 is right for a
   typical interactive UI; a public API serving polling clients usually
   wants 300+.
3. Add carve-outs for webhooks and user-content endpoints. False
   positives on a payment webhook cost real money.
4. If you run multiple uvicorn workers, remember the rate limit is
   per-worker. The cluster-wide limit lands in a later release.
