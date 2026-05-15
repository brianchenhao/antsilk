from __future__ import annotations

import asyncio
import ipaddress

import pytest

from antsilk.rules.threat_intel import (
    ThreatIntelManager,
    ThreatIntelStore,
    _merge_ranges,
    parse,
)


def _ip(s: str) -> int:
    return int(ipaddress.IPv4Address(s))


# ----------------------------- parse ----------------------------

def test_parse_simple_cidr() -> None:
    ranges = parse("1.2.3.0/24\n5.6.7.8/32\n")
    assert ranges == [
        (_ip("1.2.3.0"), _ip("1.2.3.255")),
        (_ip("5.6.7.8"), _ip("5.6.7.8")),
    ]


def test_parse_skips_blank_and_comment_lines() -> None:
    text = "\n# hash comment\n1.2.3.0/24\n// slash comment\n; spamhaus comment\n   \n"
    assert parse(text) == [(_ip("1.2.3.0"), _ip("1.2.3.255"))]


def test_parse_handles_inline_metadata() -> None:
    # Spamhaus DROP format: CIDR followed by `; SBL<id>`
    text = "1.2.3.0/24 ; SBL12345\n"
    assert parse(text) == [(_ip("1.2.3.0"), _ip("1.2.3.255"))]


def test_parse_handles_whitespace_separated_metadata() -> None:
    text = "1.2.3.0/24    extra notes about this range\n"
    assert parse(text) == [(_ip("1.2.3.0"), _ip("1.2.3.255"))]


def test_parse_skips_malformed_lines() -> None:
    text = "not-an-ip\n1.2.3.0/24\nalso garbage\n999.999.999.999\n"
    assert parse(text) == [(_ip("1.2.3.0"), _ip("1.2.3.255"))]


def test_parse_skips_ipv6_entries() -> None:
    text = "2001:db8::/32\n1.2.3.0/24\n"
    assert parse(text) == [(_ip("1.2.3.0"), _ip("1.2.3.255"))]


def test_parse_merges_overlapping_ranges() -> None:
    # 1.2.3.0/24 covers .0-.255; 1.2.3.128/25 covers .128-.255 → merges
    ranges = parse("1.2.3.0/24\n1.2.3.128/25\n")
    assert ranges == [(_ip("1.2.3.0"), _ip("1.2.3.255"))]


def test_parse_merges_adjacent_ranges() -> None:
    # 1.2.3.0/25 (.0-.127) and 1.2.3.128/25 (.128-.255) are adjacent
    ranges = parse("1.2.3.0/25\n1.2.3.128/25\n")
    assert ranges == [(_ip("1.2.3.0"), _ip("1.2.3.255"))]


def test_parse_keeps_disjoint_ranges_separate() -> None:
    ranges = parse("1.2.3.0/24\n5.6.7.0/24\n")
    assert ranges == [
        (_ip("1.2.3.0"), _ip("1.2.3.255")),
        (_ip("5.6.7.0"), _ip("5.6.7.255")),
    ]


def test_parse_returns_empty_on_empty_input() -> None:
    assert parse("") == []
    assert parse("\n\n  \n") == []


def test_parse_returns_empty_on_only_comments() -> None:
    assert parse("# only\n; comments\n// here\n") == []


# --------------------------- _merge_ranges ----------------------

def test_merge_ranges_empty() -> None:
    assert _merge_ranges([]) == []


def test_merge_ranges_single() -> None:
    r = [(0, 10)]
    assert _merge_ranges(r) == r


def test_merge_ranges_chains_overlaps() -> None:
    r = [(0, 10), (5, 15), (12, 20), (100, 200)]
    assert _merge_ranges(r) == [(0, 20), (100, 200)]


# -------------------------- ThreatIntelStore --------------------

def test_store_empty_returns_false() -> None:
    store = ThreatIntelStore()
    assert store.lookup("1.2.3.4") is False


def test_store_lookup_hit_and_miss() -> None:
    store = ThreatIntelStore()
    store.load(
        [
            (_ip("10.0.0.0"), _ip("10.0.0.255")),
            (_ip("192.168.1.0"), _ip("192.168.1.255")),
        ]
    )
    assert store.lookup("10.0.0.0") is True
    assert store.lookup("10.0.0.50") is True
    assert store.lookup("10.0.0.255") is True
    assert store.lookup("10.0.1.0") is False
    assert store.lookup("192.168.1.128") is True
    assert store.lookup("192.168.2.0") is False
    assert store.lookup("8.8.8.8") is False


def test_store_lookup_invalid_ip_returns_false() -> None:
    store = ThreatIntelStore()
    store.load([(_ip("1.2.3.0"), _ip("1.2.3.255"))])
    assert store.lookup("not-an-ip") is False
    assert store.lookup("999.999.999.999") is False
    assert store.lookup("") is False
    # IPv6 input — v0.1.0 IPv4 only
    assert store.lookup("::1") is False


def test_store_load_replaces_previous() -> None:
    store = ThreatIntelStore()
    store.load([(_ip("1.2.3.0"), _ip("1.2.3.255"))])
    assert store.lookup("1.2.3.50") is True
    store.load([(_ip("5.6.7.0"), _ip("5.6.7.255"))])
    assert store.lookup("1.2.3.50") is False
    assert store.lookup("5.6.7.50") is True


def test_store_size_reflects_range_count() -> None:
    store = ThreatIntelStore()
    assert store.size() == 0
    store.load([(_ip("1.0.0.0"), _ip("1.0.0.255")), (_ip("2.0.0.0"), _ip("2.0.0.255"))])
    assert store.size() == 2


# ------------------------ ThreatIntelManager --------------------

def test_manager_refresh_with_synthetic_feed() -> None:
    """Plan step 7: synthetic feed containing 127.0.0.1 blocks loopback."""

    def fake_fetcher(_url: str) -> str:
        return "127.0.0.0/24\n"

    async def go() -> None:
        mgr = ThreatIntelManager(feeds=["fake://test"], fetcher=fake_fetcher)
        await mgr.refresh()
        assert mgr.lookup("127.0.0.1") is True
        assert mgr.lookup("127.0.0.255") is True
        assert mgr.lookup("8.8.8.8") is False

    asyncio.run(go())


def test_manager_aggregates_multiple_feeds() -> None:
    feeds_data = {
        "feed-a": "1.1.1.0/24\n",
        "feed-b": "2.2.2.0/24\n",
    }

    def fake(url: str) -> str:
        return feeds_data[url]

    async def go() -> None:
        mgr = ThreatIntelManager(feeds=list(feeds_data.keys()), fetcher=fake)
        await mgr.refresh()
        assert mgr.lookup("1.1.1.100") is True
        assert mgr.lookup("2.2.2.100") is True
        assert mgr.lookup("3.3.3.3") is False

    asyncio.run(go())


def test_manager_first_fetch_failure_serves_empty_store() -> None:
    """Bootstrap fail-open: middleware boots empty, app still serves."""

    def boom(_url: str) -> str:
        raise RuntimeError("network down")

    async def go() -> None:
        mgr = ThreatIntelManager(feeds=["a", "b"], fetcher=boom)
        await mgr.refresh()  # must not raise
        assert mgr.store.size() == 0
        assert mgr.lookup("127.0.0.1") is False

    asyncio.run(go())


def test_manager_keeps_previous_set_when_all_feeds_fail() -> None:
    state = {"call": 0}

    def alternating(url: str) -> str:
        state["call"] += 1
        if state["call"] <= 1:
            return "10.0.0.0/8\n"
        raise RuntimeError("transient failure")

    async def go() -> None:
        mgr = ThreatIntelManager(feeds=["a"], fetcher=alternating)
        await mgr.refresh()
        assert mgr.lookup("10.1.2.3") is True
        prev_size = mgr.store.size()
        # Second refresh — fetcher raises; previous set must survive.
        await mgr.refresh()
        assert mgr.store.size() == prev_size
        assert mgr.lookup("10.1.2.3") is True

    asyncio.run(go())


def test_manager_uses_surviving_feed_when_one_fails() -> None:
    def half(url: str) -> str:
        if url == "ok":
            return "1.1.1.0/24\n"
        raise RuntimeError("dead feed")

    async def go() -> None:
        mgr = ThreatIntelManager(feeds=["ok", "broken"], fetcher=half)
        await mgr.refresh()
        # The successful feed replaces the store; broken feed is ignored.
        assert mgr.lookup("1.1.1.50") is True

    asyncio.run(go())


def test_manager_populate_bypasses_network() -> None:
    def must_not_run(_url: str) -> str:
        raise AssertionError("fetcher was called but populate should skip it")

    mgr = ThreatIntelManager(feeds=["a"], fetcher=must_not_run)
    mgr.populate([(_ip("203.0.113.0"), _ip("203.0.113.255"))])
    assert mgr.lookup("203.0.113.42") is True


def test_manager_empty_feed_list_is_noop() -> None:
    async def go() -> None:
        mgr = ThreatIntelManager(feeds=[])
        await mgr.refresh()
        assert mgr.store.size() == 0
        assert mgr.lookup("8.8.8.8") is False

    asyncio.run(go())


def test_manager_ensure_running_skips_when_store_populated() -> None:
    """Lazy-start should not spawn a fetch task if the store is already loaded.

    This is what stops test runs from making real network requests when an
    AntsilkMiddleware is built with threat_intel enabled.
    """
    fetched = []

    def fetcher(url: str) -> str:
        fetched.append(url)
        return ""

    async def go() -> None:
        mgr = ThreatIntelManager(feeds=["a"], fetcher=fetcher)
        mgr.populate([(_ip("1.1.1.0"), _ip("1.1.1.0"))])
        mgr.ensure_running()
        # Give the loop a tick in case a task was scheduled.
        await asyncio.sleep(0)
        assert mgr._task is None
        assert fetched == []

    asyncio.run(go())
