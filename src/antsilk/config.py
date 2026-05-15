from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AntsilkConfig:
    """User-facing middleware configuration.

    Fields default to the values appropriate for a typical FastAPI app.
    New fields land in later phases with backwards-compatible defaults —
    callers that pass ``AntsilkConfig()`` should keep working across the
    v0.1.x range.
    """

    requests_per_minute: int = 60
