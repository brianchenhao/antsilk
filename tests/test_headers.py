from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from antsilk import AntsilkConfig, AntsilkMiddleware
from antsilk.rules.headers import HeaderCheck, inspect


def _build_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        AntsilkMiddleware,
        config=AntsilkConfig(threat_intel_enabled=False),
    )

    @app.get("/")
    async def root() -> dict[str, bool]:
        return {"ok": True}

    return app


# ---------------------- legitimate clients pass -----------------

@pytest.mark.parametrize(
    "user_agent",
    [
        b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        b"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        b"curl/8.4.0",
        b"HTTPie/3.2.2",
        b"python-httpx/0.27.0",
        b"PostmanRuntime/7.36.0",
    ],
)
def test_legit_user_agents_pass(user_agent: bytes) -> None:
    assert inspect([(b"user-agent", user_agent)]) is None


# ---------------------- missing User-Agent ----------------------

def test_no_user_agent_header_is_missing() -> None:
    result = inspect([])
    assert isinstance(result, HeaderCheck)
    assert result.rule == "missing_user_agent"


def test_empty_user_agent_is_missing() -> None:
    result = inspect([(b"user-agent", b"")])
    assert result is not None
    assert result.rule == "missing_user_agent"


def test_whitespace_only_user_agent_is_missing() -> None:
    result = inspect([(b"user-agent", b"   \t  ")])
    assert result is not None
    assert result.rule == "missing_user_agent"


# ----------------------- known-bad UAs --------------------------

@pytest.mark.parametrize(
    "user_agent",
    [
        b"sqlmap/1.7.2#stable (https://sqlmap.org)",
        b"Mozilla/5.0 sqlmap embedded",
        b"Nikto/2.5.0",
        b"masscan/1.3.2",
        b"Nmap Scripting Engine; https://nmap.org/book/nse.html",
    ],
)
def test_bad_user_agents_blocked(user_agent: bytes) -> None:
    result = inspect([(b"user-agent", user_agent)])
    assert result is not None
    assert result.rule == "bad_user_agent"


def test_legit_ua_containing_substring_of_tool_name_passes() -> None:
    # "nmap" must be word-bounded — strings that merely contain those
    # letters should not false-positive.
    assert inspect([(b"user-agent", b"Mozilla/5.0 (trapnmapper)")]) is None


# ----------------------- malformed Cookie -----------------------

def test_legit_cookie_passes() -> None:
    headers = [
        (b"user-agent", b"Mozilla/5.0"),
        (b"cookie", b"session_id=abc123; theme=dark; csrf=AbCdEf-1234"),
    ]
    assert inspect(headers) is None


def test_absent_cookie_header_passes() -> None:
    assert inspect([(b"user-agent", b"Mozilla/5.0")]) is None


@pytest.mark.parametrize(
    "cookie",
    [
        b"",                             # empty
        b"   ",                          # whitespace only
        b"justaword",                    # no '='
        b"name=val\x00ue",               # null byte
        b"name=val\xffue",               # non-ASCII byte
        b"name=val\x07ue",               # bell character
    ],
)
def test_malformed_cookies_blocked(cookie: bytes) -> None:
    headers = [
        (b"user-agent", b"Mozilla/5.0"),
        (b"cookie", cookie),
    ]
    result = inspect(headers)
    assert result is not None
    assert result.rule == "malformed_cookie"


# ------------------- precedence: UA checked before Cookie -------

def test_missing_ua_blocks_before_cookie_check() -> None:
    headers = [(b"cookie", b"justaword")]
    result = inspect(headers)
    assert result is not None
    assert result.rule == "missing_user_agent"


def test_bad_ua_blocks_before_cookie_check() -> None:
    headers = [
        (b"user-agent", b"sqlmap/1.7"),
        (b"cookie", b"justaword"),
    ]
    result = inspect(headers)
    assert result is not None
    assert result.rule == "bad_user_agent"


# --------------------- HTTP-level integration -------------------

@pytest.mark.parametrize(
    "user_agent",
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "curl/8.4.0",
        "HTTPie/3.2.2",
    ],
)
def test_middleware_allows_legit_user_agents(user_agent: str) -> None:
    client = TestClient(_build_app())
    response = client.get("/", headers={"User-Agent": user_agent})
    assert response.status_code == 200


@pytest.mark.parametrize(
    "user_agent",
    [
        "sqlmap/1.7.2#stable (https://sqlmap.org)",
        "Nikto/2.5.0",
        "masscan/1.3.2",
        "Nmap Scripting Engine",
    ],
)
def test_middleware_blocks_known_bad_user_agents(user_agent: str) -> None:
    client = TestClient(_build_app())
    response = client.get("/", headers={"User-Agent": user_agent})
    assert response.status_code == 403
    assert response.json() == {"error": "blocked"}


def test_middleware_blocks_empty_user_agent() -> None:
    client = TestClient(_build_app())
    response = client.get("/", headers={"User-Agent": ""})
    assert response.status_code == 403
    assert response.json() == {"error": "blocked"}


def test_middleware_blocks_malformed_cookie() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/",
        headers={"User-Agent": "Mozilla/5.0", "Cookie": "justaword"},
    )
    assert response.status_code == 403
    assert response.json() == {"error": "blocked"}


def test_middleware_allows_legit_cookie() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/",
        headers={
            "User-Agent": "Mozilla/5.0",
            "Cookie": "session=abc123; theme=dark",
        },
    )
    assert response.status_code == 200
