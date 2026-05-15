from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

from antsilk.config import AntsilkConfig
from antsilk.rules.rate_limit import RateLimiter

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_RATE_LIMITED_BODY = json.dumps({"error": "rate_limited"}).encode()


class AntsilkMiddleware:
    """Drop-in security middleware for ASGI apps.

    v0.1.0 currently enforces a per-IP token-bucket rate limit. Pattern
    scanning, header checks, and threat-intel filtering land in later
    phases without breaking this constructor.
    """

    def __init__(
        self,
        app: ASGIApp,
        config: AntsilkConfig | None = None,
    ) -> None:
        self.app = app
        self.config = config or AntsilkConfig()
        self._rate_limiter = RateLimiter(self.config.requests_per_minute)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        ip = _client_ip(scope)
        if not self._rate_limiter.allow(ip):
            await _send_rate_limited(send)
            return

        await self.app(scope, receive, send)


def _client_ip(scope: Scope) -> str:
    client = scope.get("client")
    if not client:
        return "unknown"
    return client[0]


async def _send_rate_limited(send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 429,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(_RATE_LIMITED_BODY)).encode()),
                (b"retry-after", b"60"),
            ],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": _RATE_LIMITED_BODY,
        }
    )
