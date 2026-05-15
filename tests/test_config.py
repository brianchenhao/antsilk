from __future__ import annotations

import asyncio
import ipaddress

from fastapi import FastAPI
from fastapi.testclient import TestClient

from antsilk import AntsilkConfig, AntsilkMiddleware, RouteRule


def _ip(s: str) -> int:
    return int(ipaddress.IPv4Address(s))


# ----------------------- RouteRule dataclass --------------------

def test_route_rule_defaults_skip_nothing() -> None:
    rule = RouteRule(path="/anything")
    assert rule.path == "/anything"
    assert rule.skip_rate_limit is False
    assert rule.skip_pattern_scan is False
    assert rule.skip_body_scan is False
    assert rule.skip_threat_intel is False


def test_route_rule_is_frozen() -> None:
    rule = RouteRule(path="/x")
    try:
        rule.path = "/y"  # type: ignore[misc]
    except Exception:
        return
    raise AssertionError("RouteRule should be frozen")


def test_default_config_has_no_route_rules() -> None:
    assert AntsilkConfig().route_rules == ()


# ----------------------- skip_pattern_scan ----------------------

def test_skip_pattern_scan_bypasses_attack_on_matching_route() -> None:
    app = FastAPI()
    app.add_middleware(
        AntsilkMiddleware,
        config=AntsilkConfig(
            threat_intel_enabled=False,
            route_rules=(
                RouteRule(path="/chat", skip_pattern_scan=True),
            ),
        ),
    )

    @app.get("/chat")
    async def chat() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/api/users")
    async def users() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    # /chat carries an SQLi-shaped payload but the route is whitelisted.
    assert client.get("/chat?q=1 OR 1=1").status_code == 200
    # Unwhitelisted route still gets 403.
    assert client.get("/api/users?q=1 OR 1=1").status_code == 403


def test_skip_pattern_scan_glob_matches_subpaths() -> None:
    app = FastAPI()
    app.add_middleware(
        AntsilkMiddleware,
        config=AntsilkConfig(
            threat_intel_enabled=False,
            route_rules=(
                RouteRule(path="/ugc/*", skip_pattern_scan=True),
            ),
        ),
    )

    @app.get("/ugc/comments")
    async def comments() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    assert client.get("/ugc/comments?text=<script>alert(1)</script>").status_code == 200


# ----------------------- skip_rate_limit ------------------------

def test_skip_rate_limit_lets_webhook_burst_without_429() -> None:
    app = FastAPI()
    app.add_middleware(
        AntsilkMiddleware,
        config=AntsilkConfig(
            requests_per_minute=2,
            threat_intel_enabled=False,
            route_rules=(
                RouteRule(path="/webhooks/*", skip_rate_limit=True),
            ),
        ),
    )

    @app.post("/webhooks/stripe")
    async def stripe() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/api")
    async def api() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    # The webhook should never trip rate limit even when called more
    # times than the per-minute budget.
    for _ in range(10):
        assert client.post("/webhooks/stripe").status_code == 200

    # The non-webhook route still hits the limit at request #3.
    assert client.get("/api").status_code == 200
    assert client.get("/api").status_code == 200
    assert client.get("/api").status_code == 429


# ----------------------- skip_threat_intel ----------------------

def _drive_with_threat_intel(
    *,
    client_ip: str,
    path: str,
    route_rules: tuple[RouteRule, ...],
    block_ip: str,
) -> int:
    """Direct ASGI drive — TestClient sets a non-IPv4 client tuple, so
    threat-intel lookups can't hit. Same trick as test_threat_intel.py."""

    async def inner(scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = AntsilkMiddleware(
        inner,
        config=AntsilkConfig(
            threat_intel_feeds=("fake://",),
            route_rules=route_rules,
        ),
    )
    assert mw._threat_intel is not None
    mw._threat_intel.populate([(_ip(block_ip), _ip(block_ip))])

    async def recv():  # type: ignore[no-untyped-def]
        return {"type": "http.request", "body": b"", "more_body": False}

    statuses: list[int] = []

    async def send(msg):  # type: ignore[no-untyped-def]
        if msg["type"] == "http.response.start":
            statuses.append(msg["status"])

    scope = {
        "type": "http",
        "client": (client_ip, 0),
        "method": "GET",
        "path": path,
        "query_string": b"",
        "headers": [(b"user-agent", b"Mozilla/5.0")],
    }
    asyncio.run(mw(scope, recv, send))
    return statuses[0]


def test_skip_threat_intel_lets_blocklisted_ip_through_on_whitelisted_route() -> None:
    code = _drive_with_threat_intel(
        client_ip="127.0.0.1",
        path="/webhooks/billplz",
        route_rules=(RouteRule(path="/webhooks/*", skip_threat_intel=True),),
        block_ip="127.0.0.1",
    )
    assert code == 200


def test_skip_threat_intel_still_blocks_blocklisted_ip_on_other_route() -> None:
    code = _drive_with_threat_intel(
        client_ip="127.0.0.1",
        path="/api/users",
        route_rules=(RouteRule(path="/webhooks/*", skip_threat_intel=True),),
        block_ip="127.0.0.1",
    )
    assert code == 403


# ----------------------- precedence -----------------------------

def test_first_matching_route_rule_wins() -> None:
    """A more specific rule placed before a catch-all should win."""
    app = FastAPI()
    app.add_middleware(
        AntsilkMiddleware,
        config=AntsilkConfig(
            threat_intel_enabled=False,
            route_rules=(
                RouteRule(path="/api/special", skip_pattern_scan=True),
                RouteRule(path="/api/*", skip_pattern_scan=False),
            ),
        ),
    )

    @app.get("/api/special")
    async def special() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/api/other")
    async def other() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    # /api/special hits the first rule → pattern scan skipped → 200
    assert client.get("/api/special?id=1 OR 1=1").status_code == 200
    # /api/other matches only the catch-all → pattern scan runs → 403
    assert client.get("/api/other?id=1 OR 1=1").status_code == 403


def test_no_matching_route_rule_means_all_rules_apply() -> None:
    app = FastAPI()
    app.add_middleware(
        AntsilkMiddleware,
        config=AntsilkConfig(
            threat_intel_enabled=False,
            route_rules=(
                RouteRule(path="/webhooks/*", skip_pattern_scan=True),
            ),
        ),
    )

    @app.get("/api/items")
    async def items() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    assert client.get("/api/items?id=1 OR 1=1").status_code == 403


# ----------------------- header rule has no skip ----------------

def test_header_rule_has_no_skip_flag_even_on_whitelisted_route() -> None:
    """Header sanity checks intentionally have no skip flag — bypassing
    missing-UA detection is almost never what the adopter wants."""
    app = FastAPI()
    app.add_middleware(
        AntsilkMiddleware,
        config=AntsilkConfig(
            threat_intel_enabled=False,
            route_rules=(
                RouteRule(
                    path="/webhooks/*",
                    skip_rate_limit=True,
                    skip_pattern_scan=True,
                    skip_threat_intel=True,
                ),
            ),
        ),
    )

    @app.get("/webhooks/stripe")
    async def stripe() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    # No User-Agent → header rule fires regardless of skip flags.
    response = client.get("/webhooks/stripe", headers={"User-Agent": ""})
    assert response.status_code == 403
