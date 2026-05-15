from __future__ import annotations

import re
from dataclasses import dataclass

_SQLI = re.compile(
    r"\b(union\s+select|or\s+1\s*=\s*1|--\s|/\*.*\*/|xp_cmdshell)\b",
    re.IGNORECASE,
)
_XSS = re.compile(
    r"<script[^>]*>|javascript:|on(load|error|click)\s*=",
    re.IGNORECASE,
)
_PATH_TRAVERSAL = re.compile(
    r"\.\./|\.\.%2f|%2e%2e/",
    re.IGNORECASE,
)

_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("sqli", _SQLI),
    ("xss", _XSS),
    ("path_traversal", _PATH_TRAVERSAL),
)


@dataclass(frozen=True)
class PatternMatch:
    rule: str
    matched: str


def scan(text: str) -> PatternMatch | None:
    """Return the first pattern that matches the input, or None."""
    for rule, pattern in _RULES:
        hit = pattern.search(text)
        if hit:
            return PatternMatch(rule=rule, matched=hit.group(0))
    return None
