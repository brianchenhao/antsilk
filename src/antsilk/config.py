from __future__ import annotations

from dataclasses import dataclass, field

from antsilk.rules.threat_intel import DEFAULT_FEEDS
from antsilk.sinks.base import EventSink
from antsilk.sinks.sqlite import SQLiteSink


@dataclass(frozen=True)
class RouteRule:
    """Per-route override.

    ``path`` is a shell-style glob (``fnmatch`` semantics) matched against
    the incoming request path with ``fnmatchcase`` — case-sensitive on
    every platform. Each ``skip_*`` flag opts the matched route out of
    one rule layer:

    * ``skip_rate_limit`` — webhook callbacks from a single source IP
      legitimately burst far above a per-IP limit.
    * ``skip_pattern_scan`` — user-content endpoints (chat, comments)
      will routinely contain strings that look like SQLi or XSS to the
      regex scanner.
    * ``skip_body_scan`` — reserved for v0.3.0 when body scanning lands;
      a no-op today, defined now so adopter configs survive the upgrade.
    * ``skip_threat_intel`` — accept traffic from any IP, including
      ones on FireHOL / Spamhaus. Rare; reserved for payment webhooks.

    Header sanity checks have no skip flag — bypassing missing-UA or
    sqlmap-UA detection is almost never what an adopter wants.
    """

    path: str
    skip_rate_limit: bool = False
    skip_pattern_scan: bool = False
    skip_body_scan: bool = False
    skip_threat_intel: bool = False


@dataclass
class AntsilkConfig:
    """User-facing middleware configuration.

    Fields default to the values appropriate for a typical FastAPI app.
    New fields land in later phases with backwards-compatible defaults —
    callers that pass ``AntsilkConfig()`` should keep working across the
    v0.1.x range.
    """

    requests_per_minute: int = 60
    threat_intel_enabled: bool = True
    threat_intel_feeds: tuple[str, ...] = DEFAULT_FEEDS
    threat_intel_refresh_hours: int = 6
    sink: EventSink = field(default_factory=SQLiteSink)
    route_rules: tuple[RouteRule, ...] = ()
