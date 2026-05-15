from __future__ import annotations

import asyncio

from fastapi import FastAPI
from fastapi.testclient import TestClient

from antsilk import AntsilkConfig, AntsilkMiddleware


def test_middleware_passes_request_through(client: TestClient) -> None:
    response = client.get("/ping")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_middleware_returns_429_when_rate_limit_exceeded() -> None:
    app = FastAPI()
    app.add_middleware(
        AntsilkMiddleware,
        config=AntsilkConfig(requests_per_minute=3, threat_intel_enabled=False),
    )

    @app.get("/")
    async def root() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    for _ in range(3):
        assert client.get("/").status_code == 200

    response = client.get("/")
    assert response.status_code == 429
    assert response.json() == {"error": "rate_limited"}
    assert response.headers["retry-after"] == "60"
    assert response.headers["content-type"] == "application/json"


def test_middleware_passes_through_non_http_scope() -> None:
    """Lifespan + websocket scopes must skip every rule and hand off to
    the inner app unchanged — antsilk is HTTP-only in v0.1.0."""
    seen: list[dict[str, object]] = []

    async def inner(scope, receive, send):  # type: ignore[no-untyped-def]
        seen.append(scope)

    mw = AntsilkMiddleware(
        inner, config=AntsilkConfig(threat_intel_enabled=False)
    )

    async def recv():  # type: ignore[no-untyped-def]
        return {"type": "lifespan.startup"}

    async def send(_msg):  # type: ignore[no-untyped-def]
        return None

    asyncio.run(mw({"type": "lifespan"}, recv, send))
    assert len(seen) == 1
    assert seen[0]["type"] == "lifespan"


def test_middleware_handles_scope_without_client() -> None:
    """ASGI servers MAY omit ``scope['client']`` (e.g. unix socket). The
    rule layer should still see *some* ip, and the request should not
    crash because of the missing tuple."""

    async def inner(scope, receive, send):  # type: ignore[no-untyped-def]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = AntsilkMiddleware(
        inner, config=AntsilkConfig(threat_intel_enabled=False)
    )

    async def recv():  # type: ignore[no-untyped-def]
        return {"type": "http.request", "body": b"", "more_body": False}

    statuses: list[int] = []

    async def send(msg):  # type: ignore[no-untyped-def]
        if msg["type"] == "http.response.start":
            statuses.append(msg["status"])

    scope = {
        "type": "http",
        "client": None,
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [(b"user-agent", b"Mozilla/5.0")],
    }
    asyncio.run(mw(scope, recv, send))
    assert statuses == [200]


def test_middleware_allows_request_with_empty_path() -> None:
    """A scope with an empty path string must still reach the inner app —
    the pattern scanner short-circuits the path branch when there is
    nothing to scan."""

    async def inner(scope, receive, send):  # type: ignore[no-untyped-def]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = AntsilkMiddleware(
        inner, config=AntsilkConfig(threat_intel_enabled=False)
    )

    async def recv():  # type: ignore[no-untyped-def]
        return {"type": "http.request", "body": b"", "more_body": False}

    statuses: list[int] = []

    async def send(msg):  # type: ignore[no-untyped-def]
        if msg["type"] == "http.response.start":
            statuses.append(msg["status"])

    scope = {
        "type": "http",
        "client": ("9.9.9.9", 0),
        "method": "GET",
        "path": "",
        "query_string": b"",
        "headers": [(b"user-agent", b"Mozilla/5.0")],
    }
    asyncio.run(mw(scope, recv, send))
    assert statuses == [200]
