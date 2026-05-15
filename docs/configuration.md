# Configuration

Every knob lives on the `AntsilkConfig` dataclass. Construct one, pass
it to `add_middleware`, done.

```python
from antsilk import AntsilkConfig, AntsilkMiddleware

app.add_middleware(
    AntsilkMiddleware,
    config=AntsilkConfig(requests_per_minute=300),
)
```

The defaults are picked for a typical FastAPI app — for most projects
you only need to touch one or two fields.

## All fields

| Field                        | Type                  | Default                                         | What it does                                                                 |
| ---------------------------- | --------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------- |
| `requests_per_minute`        | `int`                 | `60`                                            | Per-IP token-bucket capacity *and* refill rate (capacity tokens / 60s).      |
| `threat_intel_enabled`       | `bool`                | `True`                                          | Master switch for the IP blocklist rule. `False` skips both fetch and lookup. |
| `threat_intel_feeds`         | `tuple[str, ...]`     | FireHOL Level 1 + Spamhaus DROP                  | URLs of plaintext CIDR / IP-range feeds.                                     |
| `threat_intel_refresh_hours` | `int`                 | `6`                                             | Background refresh interval.                                                  |
| `sink`                       | `EventSink`           | `SQLiteSink()` → `./antsilk_events.db`           | Where blocks are recorded.                                                    |
| `route_rules`                | `tuple[RouteRule,..]` | `()`                                            | Per-route carve-outs — see [Per-route overrides](per-route-overrides.md).    |

## `requests_per_minute`

The token bucket has `requests_per_minute` capacity and refills at
`requests_per_minute / 60` tokens per second. So the default of 60
means an IP can burst 60 requests instantly and then sustain 1 req/s
afterwards.

Set it honestly for your traffic:

- Interactive UI (one user, a few clicks per second): `60` is fine.
- Public API with polling clients: usually `300` or higher.
- Internal-only service behind a VPN: high enough that you only hit it
  on genuine abuse.

```python
AntsilkConfig(requests_per_minute=300)
```

## `threat_intel_*`

The threat-intel rule pulls plaintext CIDR feeds at startup, parses
them into a sorted range list, and does an O(log N) bisect lookup on
every request. Refresh is a background task that re-fetches every
`threat_intel_refresh_hours` and atomically swaps the in-memory store.

If a refresh fails, the previous in-memory blocklist is kept and a
warning is logged. If the *very first* fetch fails (cold boot, no
network), the middleware boots with an empty set and serves traffic —
threat-intel never crashes your app.

Disable entirely for offline development:

```python
AntsilkConfig(threat_intel_enabled=False)
```

Use a custom feed (e.g. an internal IOC list served over HTTPS):

```python
AntsilkConfig(
    threat_intel_feeds=(
        "https://intel.example.com/internal-block.txt",
        "https://iplists.firehol.org/files/firehol_level1.netset",
    ),
)
```

Feed format is tolerant:

- One CIDR per line. `1.2.3.0/24`, `5.6.7.8/32`, or bare `1.2.3.4`.
- Comment lines start with `#`, `//`, or `;` (Spamhaus DROP uses `;`).
- Inline metadata after the first whitespace token is ignored.
- IPv6 entries are skipped silently — v0.1.0 is IPv4 only.

## `sink`

Sinks are anything that conforms to the `EventSink` protocol:

```python
from antsilk import Event

class EventSink(Protocol):
    def write(self, event: Event) -> None: ...
```

Three sinks ship in the box.

### `SQLiteSink` (default)

```python
from antsilk import AntsilkConfig, SQLiteSink

AntsilkConfig(sink=SQLiteSink(path="/var/lib/antsilk/events.db"))
```

- WAL mode on, so concurrent readers (a stats dashboard, an analyst at
  the CLI) don't block the writer.
- Lazy — the database file is created on the first block, not on import.
- Schema is `events(id, timestamp, ip_address, method, path,
  rule_triggered, severity, response_code, user_agent, app_id,
  event_data)`. Indexed on `timestamp`, `ip_address`, `rule_triggered`.
- `event_data` is a JSON string with rule-specific detail (matched
  excerpt, triggering feed name, etc.).

Make sure `path` is on a persistent volume in production — events on an
ephemeral container filesystem vanish on restart.

### `JSONLinesSink`

```python
from antsilk import AntsilkConfig, JSONLinesSink

AntsilkConfig(sink=JSONLinesSink(path="antsilk_events.jsonl"))
```

Appends one JSON object per line. Useful when you already have a log
shipper (Vector, Filebeat, Promtail) tailing files into your
observability pipeline.

### `RemoteSink` (stub in v0.1.0)

```python
from antsilk import AntsilkConfig, RemoteSink

AntsilkConfig(sink=RemoteSink(endpoint="https://api.antsilk.com/events"))
```

Construction works so adopter config code compiles today. `write()`
raises `NotImplementedError` — real HTTP transport lands in v0.5.0.

### A custom sink

Anything with a sync `write(event)` method works. Sinks are called via
`asyncio.to_thread`, so blocking I/O is fine. Exceptions raised in
`write()` are caught and logged — a broken sink never propagates to
your route handler.

```python
class PostgresSink:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    def write(self, event: Event) -> None:
        # synchronous psycopg insert
        ...

AntsilkConfig(sink=PostgresSink(dsn="postgres://..."))
```

## `route_rules`

Per-route carve-outs. See **[Per-route overrides](per-route-overrides.md)** —
this is the page most adopters spend the most time on after the first
deploy.

## Order of layers

The layers run in this order on every request:

1. **threat-intel** — cheapest reject, runs first
2. **rate limit** — per-IP token bucket
3. **headers** — structural checks (missing UA, bad UA, malformed Cookie)
4. **patterns** — SQLi / XSS / path traversal regex

The first match short-circuits. Only one event is written per blocked
request, tagged with the layer that fired.
