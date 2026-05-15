# Per-route overrides

Antsilk's defaults are picked for a typical FastAPI app — a per-IP rate
limit, a regex pattern scan over the URL and headers, a threat-intel IP
blocklist, and a structural header check. A handful of route shapes
break these defaults:

- **Webhook callbacks** (Stripe, Billplz, GitHub) burst from a single
  source IP far above any reasonable per-IP rate limit.
- **User-content endpoints** (chat, comments, anywhere a user types
  prose) routinely contain strings that look like SQLi or XSS to a
  regex.
- **Payment webhooks** occasionally originate from IPs that overlap
  IOC feeds — Stripe and Billplz both publish their source IP ranges
  but those ranges drift, and a stale match means dropped revenue.

`RouteRule` exists to opt specific paths out of specific rule layers.

## Quick example

```python
from antsilk import AntsilkConfig, AntsilkMiddleware, RouteRule

config = AntsilkConfig(
    route_rules=(
        RouteRule(path="/webhooks/*", skip_rate_limit=True, skip_threat_intel=True),
        RouteRule(path="/chat",       skip_pattern_scan=True),
        RouteRule(path="/upload",     skip_body_scan=True),
    ),
)
app.add_middleware(AntsilkMiddleware, config=config)
```

## Matching semantics

- `path` is a shell-style glob matched with `fnmatch.fnmatchcase` —
  case-sensitive on every platform, including Windows.
- `*` matches anything, including `/`. So `/webhooks/*` matches both
  `/webhooks/stripe` and `/webhooks/billplz/callback`.
- **First match wins.** Order your rules from most specific to least
  specific. A catch-all `/api/*` placed before `/api/special` will
  swallow the more specific rule.
- If no rule matches, every Antsilk rule layer runs as normal.

## Available skip flags

| Flag                | What it skips                                                                                     | When to use                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `skip_rate_limit`   | Per-IP token-bucket rate limiter                                                                  | Webhook endpoints where one upstream legitimately bursts                                     |
| `skip_pattern_scan` | SQLi / XSS / path-traversal regex over URL path, query string, and non-`User-Agent` header values | User-content endpoints (chat, comments) where the input is supposed to contain arbitrary text |
| `skip_body_scan`    | Reserved for v0.3.0 when body scanning lands; **no-op today**                                     | File-upload endpoints where the request body is binary and shouldn't be scanned              |
| `skip_threat_intel` | FireHOL / Spamhaus IP blocklist                                                                   | Payment webhooks where the upstream IP range may overlap an IOC feed                          |

## What you can NOT skip

The header sanity check (`bad_header` rule — missing User-Agent,
`sqlmap`/`nikto`/`masscan`/`nmap` in User-Agent, malformed Cookie) runs
on every request regardless of route rule. Bypassing those signals is
almost never what an adopter wants — every legitimate webhook source
sends a real User-Agent, and the bad-UA list is a closed set of
well-known attack tools.
