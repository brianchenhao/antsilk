from __future__ import annotations

import pytest

from antsilk.rules.patterns import scan


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
