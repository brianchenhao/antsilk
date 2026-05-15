from __future__ import annotations

from typing import Any, Awaitable, Callable

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class AntsilkMiddleware:
    """Drop-in security middleware for ASGI apps.

    v0.1.0 ships as a pass-through: the middleware accepts the standard
    ``app.add_middleware(AntsilkMiddleware)`` install shape but performs no
    inspection yet. Real rules (rate limit, pattern scanner, header checks,
    threat intel) land in later phases without breaking this constructor.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)
