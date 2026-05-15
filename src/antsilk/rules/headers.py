from __future__ import annotations

import re
from dataclasses import dataclass

_BAD_UA = re.compile(rb"\b(sqlmap|nikto|masscan|nmap)\b", re.IGNORECASE)
_PRINTABLE_ASCII = re.compile(rb"^[\t\x20-\x7e]+$")


@dataclass(frozen=True)
class HeaderCheck:
    rule: str  # "missing_user_agent" | "bad_user_agent" | "malformed_cookie"


def inspect(headers: list[tuple[bytes, bytes]]) -> HeaderCheck | None:
    """Look at structural header signals; never inspect header content for
    SQLi/XSS — that's the pattern scanner's job."""

    user_agent: bytes | None = None
    cookie: bytes | None = None
    for name, value in headers:
        if name == b"user-agent":
            user_agent = value
        elif name == b"cookie":
            cookie = value

    if user_agent is None or not user_agent.strip():
        return HeaderCheck(rule="missing_user_agent")

    if _BAD_UA.search(user_agent):
        return HeaderCheck(rule="bad_user_agent")

    if cookie is not None and not _is_valid_cookie(cookie):
        return HeaderCheck(rule="malformed_cookie")

    return None


def _is_valid_cookie(value: bytes) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    if not _PRINTABLE_ASCII.match(stripped):
        return False
    return b"=" in stripped
