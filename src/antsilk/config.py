from __future__ import annotations

from dataclasses import dataclass, field

from antsilk.rules.threat_intel import DEFAULT_FEEDS


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
