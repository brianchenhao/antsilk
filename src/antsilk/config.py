from __future__ import annotations

from dataclasses import dataclass, field

from antsilk.rules.threat_intel import DEFAULT_FEEDS
from antsilk.sinks.base import EventSink
from antsilk.sinks.sqlite import SQLiteSink


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
