from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from antsilk import AntsilkConfig, AntsilkMiddleware
from antsilk.rules.patterns import scan


def _build_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        AntsilkMiddleware,
        config=AntsilkConfig(threat_intel_enabled=False),
    )

    @app.get("/")
    async def root() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/items/{item_id}")
    async def item(item_id: str) -> dict[str, str]:
        return {"item_id": item_id}

    return app


# ----------------------------- SQLi -----------------------------

@pytest.mark.parametrize(
    "payload",
    [
        "UNION SELECT password FROM users",
        "1 OR 1=1",
        "1 or 1 = 1",
        "id=1-- DROP TABLE users",
        "SELECT/*malicious*/FROM users",
        "exec xp_cmdshell whoami",
    ],
)
def test_sqli_payloads_match(payload: str) -> None:
    match = scan(payload)
    assert match is not None
    assert match.rule == "sqli"


# ----------------------------- XSS ------------------------------

@pytest.mark.parametrize(
    "payload",
    [
        '<script>alert(1)</script>',
        '<SCRIPT src=evil.js></SCRIPT>',
        'javascript:alert(1)',
        '<img onerror=alert(1) src=x>',
        '<body onload=evil()>',
        '<a onclick=bad()>',
    ],
)
def test_xss_payloads_match(payload: str) -> None:
    match = scan(payload)
    assert match is not None
    assert match.rule == "xss"


# ------------------------ path traversal ------------------------

@pytest.mark.parametrize(
    "payload",
    [
        "../etc/passwd",
        "foo/../bar",
        "..%2fetc%2fpasswd",
        "%2e%2e/secret",
    ],
)
def test_path_traversal_payloads_match(payload: str) -> None:
    match = scan(payload)
    assert match is not None
    assert match.rule == "path_traversal"


# ------------------------- false positives ----------------------

@pytest.mark.parametrize(
    "payload",
    [
        "hello, world",
        "user@example.com",
        "search=Python tutorials",
        "I'd love a cup of tea",
        "price: $1.50",
        "order_by=name asc",
        "1+1=2",
        "/api/users",
        "/api/v1/items/42",
    ],
)
def test_legitimate_inputs_do_not_match(payload: str) -> None:
    assert scan(payload) is None


def test_scan_returns_first_matching_rule() -> None:
    # A payload could conceivably match multiple regexes — the first
    # match wins so adopters get a stable rule label.
    match = scan("UNION SELECT 1 -- <script>")
    assert match is not None
    assert match.rule == "sqli"


# ---------------------- HTTP-level integration -----------------

@pytest.mark.parametrize(
    "query",
    [
        "id=1 OR 1=1",
        "name=UNION SELECT password FROM users",
        "comment=<script>alert(1)</script>",
        "redirect=javascript:alert(1)",
        "file=../etc/passwd",
        "path=..%2fetc%2fpasswd",
    ],
)
def test_middleware_blocks_attack_payloads_with_403(query: str) -> None:
    client = TestClient(_build_app())
    response = client.get(f"/?{query}")
    assert response.status_code == 403
    assert response.json() == {"error": "blocked"}


@pytest.mark.parametrize(
    "query",
    [
        "q=hello, world",
        "search=Python tutorials",
        "email=user@example.com",
        "order_by=name asc",
        "filter=price<100",
    ],
)
def test_middleware_allows_legitimate_queries(query: str) -> None:
    client = TestClient(_build_app())
    response = client.get(f"/?{query}")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_middleware_skips_user_agent_in_pattern_scan() -> None:
    """User-Agent is the headers rule's job (Phase 4), not patterns'."""
    client = TestClient(_build_app())
    response = client.get(
        "/",
        headers={"User-Agent": "<script>alert(1)</script>"},
    )
    assert response.status_code == 200


def test_middleware_blocks_attack_pattern_in_other_header() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/",
        headers={"X-Forwarded-For": "1 OR 1=1"},
    )
    assert response.status_code == 403
    assert response.json() == {"error": "blocked"}


def test_blocked_response_does_not_echo_matched_pattern() -> None:
    """Critical Feature Detail #5: do NOT echo the matched pattern (info leak)."""
    client = TestClient(_build_app())
    response = client.get("/?id=UNION SELECT secret FROM users")
    assert response.status_code == 403
    body = response.text
    assert "UNION" not in body.upper()
    assert "secret" not in body
    assert response.json() == {"error": "blocked"}
