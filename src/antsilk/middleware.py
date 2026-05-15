from __future__ import annotations

import json
from typing import Any, Awaitable, Callable
from urllib.parse import parse_qsl

from antsilk.config import AntsilkConfig
from antsilk.rules.headers import inspect as inspect_headers
from antsilk.rules.patterns import PatternMatch, scan as scan_patterns
from antsilk.rules.rate_limit import RateLimiter
from antsilk.rules.threat_intel import ThreatIntelManager

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_RATE_LIMITED_BODY = json.dumps({"error": "rate_limited"}).encode()
_BLOCKED_BODY = json.dumps({"error": "blocked"}).encode()


class AntsilkMiddleware:
    """Drop-in security middleware for ASGI apps.

    Enforces, in order: threat-intel IP blocklist (cheapest, rejects
    hostile traffic before any other work), per-IP token-bucket rate
    limit, suspicious-header detection (missing/bad User-Agent,
    malformed Cookie), and content pattern scanning over request path,
    query-string values, and header values (except ``User-Agent``) for
    SQL injection, XSS, and path traversal. The request body is
    intentionally NOT scanned — body scanning consumes the ASGI receive
    stream and is deferred to v0.3.0 with proper buffering.
    """

    def __init__(
        self,
        app: ASGIApp,
        config: AntsilkConfig | None = None,
    ) -> None:
        self.app = app
        self.config = config or AntsilkConfig()
        self._rate_limiter = RateLimiter(self.config.requests_per_minute)
        self._threat_intel: ThreatIntelManager | None
        if self.config.threat_intel_enabled:
            self._threat_intel = ThreatIntelManager(
                feeds=self.config.threat_intel_feeds,
                refresh_seconds=self.config.threat_intel_refresh_hours * 3600,
            )
        else:
            self._threat_intel = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        ip = _client_ip(scope)

        if self._threat_intel is not None:
            self._threat_intel.ensure_running()
            if self._threat_intel.lookup(ip):
                await _send_blocked(send)
                return

        if not self._rate_limiter.allow(ip):
            await _send_rate_limited(send)
            return

        if inspect_headers(scope.get("headers", [])) is not None:
            await _send_blocked(send)
            return

        if _scan_request(scope) is not None:
            await _send_blocked(send)
            return

        await self.app(scope, receive, send)


def _client_ip(scope: Scope) -> str:
    client = scope.get("client")
    if not client:
        return "unknown"
    return client[0]


def _scan_request(scope: Scope) -> PatternMatch | None:
    path = scope.get("path", "")
    if path:
        match = scan_patterns(path)
        if match is not None:
            return match

    query_string = scope.get("query_string", b"")
    if query_string:
        decoded = query_string.decode("latin-1", errors="replace")
        # Raw query string catches encoded path-traversal sequences
        # like ..%2f before parse_qsl normalises them out.
        match = scan_patterns(decoded)
        if match is not None:
            return match
        for _, value in parse_qsl(decoded, keep_blank_values=True):
            match = scan_patterns(value)
            if match is not None:
                return match

    for name, value in scope.get("headers", []):
        if name == b"user-agent":
            continue
        match = scan_patterns(value.decode("latin-1", errors="replace"))
        if match is not None:
            return match

    return None


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


async def _send_blocked(send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(_BLOCKED_BODY)).encode()),
            ],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": _BLOCKED_BODY,
        }
    )
