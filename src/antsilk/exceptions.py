from __future__ import annotations


class AntsilkBlocked(Exception):
    """Base exception for an Antsilk-blocked request.

    The bundled ``AntsilkMiddleware`` writes a structured event and
    sends a ``403`` / ``429`` directly — it does not raise. This class
    is part of the v0.1.0 public API as a stable hook for adopters who
    subclass the middleware (or write a different ASGI integration) and
    prefer exception-driven control flow.
    """

    def __init__(
        self,
        rule_triggered: str,
        *,
        response_code: int = 403,
        message: str | None = None,
    ) -> None:
        self.rule_triggered = rule_triggered
        self.response_code = response_code
        super().__init__(message or f"blocked by antsilk rule: {rule_triggered}")


class AntsilkRateLimited(AntsilkBlocked):
    """Specialisation of :class:`AntsilkBlocked` for the rate-limit layer."""

    def __init__(
        self,
        *,
        requests_per_minute: int,
        message: str | None = None,
    ) -> None:
        self.requests_per_minute = requests_per_minute
        super().__init__(
            rule_triggered="rate_limit",
            response_code=429,
            message=message
            or f"rate limit exceeded ({requests_per_minute} req/min)",
        )
