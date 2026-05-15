from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Event:
    """Structured record of a single rule firing.

    Columns mirror the SQLite ``events`` table defined in the v0.1.0
    plan. ``event_data`` is a free-form dict that sinks should serialise
    as JSON — adopters can stash rule-specific detail (matched excerpt,
    triggering feed name, etc.) without the schema needing to change.
    """

    timestamp: str
    ip_address: str
    method: str
    path: str
    rule_triggered: str
    severity: str
    response_code: int
    user_agent: str | None = None
    app_id: str | None = None
    event_data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def now(
        cls,
        *,
        ip_address: str,
        method: str,
        path: str,
        rule_triggered: str,
        severity: str,
        response_code: int,
        user_agent: str | None = None,
        app_id: str | None = None,
        event_data: dict[str, Any] | None = None,
    ) -> "Event":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            ip_address=ip_address,
            method=method,
            path=path,
            rule_triggered=rule_triggered,
            severity=severity,
            response_code=response_code,
            user_agent=user_agent,
            app_id=app_id,
            event_data=event_data or {},
        )
