from __future__ import annotations

import asyncio
import bisect
import ipaddress
import logging
import urllib.request
from typing import Callable

_LOG = logging.getLogger("antsilk.threat_intel")

DEFAULT_FEEDS: tuple[str, ...] = (
    "https://iplists.firehol.org/files/firehol_level1.netset",
    "https://www.spamhaus.org/drop/drop.txt",
)


def fetch(url: str, timeout: float = 30.0) -> str:
    """Pull a feed body as text using only the stdlib."""
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def parse(text: str) -> list[tuple[int, int]]:
    """Tolerant CIDR parser.

    Returns a sorted, merged list of ``(start_int, end_int)`` IPv4 ranges.
    Comment lines (starting with ``#``, ``;``, or ``//``) are skipped.
    Inline metadata after the first whitespace token is ignored. Lines
    that fail to parse — including IPv6 entries — are logged at WARNING
    level and skipped, never raised.
    """
    raw_ranges: list[tuple[int, int]] = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw
        for marker in ("#", "//", ";"):
            line = line.split(marker, 1)[0]
        line = line.strip()
        if not line:
            continue
        token = line.split()[0]
        try:
            net = ipaddress.IPv4Network(token, strict=False)
        except (ValueError, ipaddress.AddressValueError):
            _LOG.warning(
                "threat_intel: skipped malformed line %d: %r", line_no, raw
            )
            continue
        raw_ranges.append(
            (int(net.network_address), int(net.broadcast_address))
        )
    return _merge_ranges(sorted(raw_ranges))


def _merge_ranges(
    ranges: list[tuple[int, int]],
) -> list[tuple[int, int]]:
    if not ranges:
        return []
    merged: list[tuple[int, int]] = [ranges[0]]
    for start, end in ranges[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


class ThreatIntelStore:
    """In-memory IPv4 blocklist with O(log N) lookup."""

    def __init__(self) -> None:
        self._ranges: list[tuple[int, int]] = []
        self._starts: list[int] = []

    def load(self, ranges: list[tuple[int, int]]) -> None:
        self._ranges = list(ranges)
        self._starts = [start for start, _ in self._ranges]

    def size(self) -> int:
        return len(self._ranges)

    def lookup(self, ip: str) -> bool:
        try:
            ip_int = int(ipaddress.IPv4Address(ip))
        except (ValueError, ipaddress.AddressValueError):
            return False
        if not self._starts:
            return False
        idx = bisect.bisect_right(self._starts, ip_int) - 1
        if idx < 0:
            return False
        start, end = self._ranges[idx]
        return start <= ip_int <= end


Fetcher = Callable[[str], str]


class ThreatIntelManager:
    """Owns the ThreatIntelStore plus a background refresh loop.

    Fail-stale semantics: when ``refresh()`` runs and every feed errors,
    the previous in-memory store is preserved and a warning is logged.
    On bootstrap (store still empty), a failed refresh leaves the store
    empty — the middleware then serves traffic without threat-intel
    filtering rather than crashing the app.
    """

    def __init__(
        self,
        feeds: tuple[str, ...] | list[str],
        *,
        refresh_seconds: float = 6 * 3600,
        fetcher: Fetcher = fetch,
    ) -> None:
        self.feeds: tuple[str, ...] = tuple(feeds)
        self.refresh_seconds = refresh_seconds
        self.fetcher: Fetcher = fetcher
        self.store = ThreatIntelStore()
        self._task: asyncio.Task[None] | None = None

    def lookup(self, ip: str) -> bool:
        return self.store.lookup(ip)

    def populate(self, ranges: list[tuple[int, int]]) -> None:
        """Direct store load — bypasses the network. Used in tests."""
        self.store.load(_merge_ranges(sorted(ranges)))

    async def refresh(self) -> None:
        """Pull every configured feed once and atomically swap the store."""
        if not self.feeds:
            return
        results = await asyncio.gather(
            *(asyncio.to_thread(self.fetcher, feed) for feed in self.feeds),
            return_exceptions=True,
        )
        collected: list[tuple[int, int]] = []
        any_succeeded = False
        for feed, result in zip(self.feeds, results):
            if isinstance(result, BaseException):
                _LOG.warning("threat_intel feed failed: %s (%s)", feed, result)
                continue
            any_succeeded = True
            collected.extend(parse(result))
        if any_succeeded:
            self.store.load(_merge_ranges(sorted(collected)))
        else:
            _LOG.warning(
                "threat_intel refresh: all %d feeds failed; keeping previous set (size=%d)",
                len(self.feeds),
                self.store.size(),
            )

    def ensure_running(self) -> None:
        """Lazy-start the background refresh loop if no task is alive.

        Tests that pre-populate the store via ``populate()`` skip
        auto-refresh — there is no benefit to fetching real feeds when
        the store is already loaded.
        """
        if self.store.size() > 0:
            return
        if self._task is not None and not self._task.done():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._task = loop.create_task(self._refresh_loop())

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    async def _refresh_loop(self) -> None:
        while True:
            try:
                await self.refresh()
            except asyncio.CancelledError:
                raise
            except Exception:
                _LOG.exception("threat_intel refresh raised; will retry")
            try:
                await asyncio.sleep(self.refresh_seconds)
            except asyncio.CancelledError:
                raise
