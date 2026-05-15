from __future__ import annotations

import antsilk


_LOCKED_V0_1_0_SURFACE = {
    "AntsilkBlocked",
    "AntsilkConfig",
    "AntsilkMiddleware",
    "AntsilkRateLimited",
    "Event",
    "EventSink",
    "JSONLinesSink",
    "RemoteSink",
    "RouteRule",
    "SQLiteSink",
    "__version__",
}


def test_locked_public_api_surface_matches_plan() -> None:
    """The v0.1.0 plan locks this exact set of symbols. Adding or removing
    one is a breaking change and must wait for v0.2.0 with a deprecation
    cycle (PLAN §Anti-Mistake Habits)."""
    assert set(antsilk.__all__) == _LOCKED_V0_1_0_SURFACE
    for name in _LOCKED_V0_1_0_SURFACE:
        assert hasattr(antsilk, name), f"public surface missing {name!r}"


def test_antsilk_blocked_is_exception_with_rule_attrs() -> None:
    err = antsilk.AntsilkBlocked("sqli")
    assert isinstance(err, Exception)
    assert err.rule_triggered == "sqli"
    assert err.response_code == 403
    assert "sqli" in str(err)


def test_antsilk_rate_limited_subclasses_antsilk_blocked() -> None:
    err = antsilk.AntsilkRateLimited(requests_per_minute=60)
    assert isinstance(err, antsilk.AntsilkBlocked)
    assert err.rule_triggered == "rate_limit"
    assert err.response_code == 429
    assert err.requests_per_minute == 60


def test_version_is_a_string() -> None:
    assert isinstance(antsilk.__version__, str)
    # v0.1.x range — locks API surface during the v0.1 line per the plan.
    assert antsilk.__version__.startswith("0.1.")
