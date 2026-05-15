from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class TokenBucket:
    """Single-IP token bucket.

    Tokens refill at ``refill_rate_per_second`` up to ``capacity``. A
    request is allowed iff at least one whole token is available, in which
    case one token is debited. All state is mutated in place — callers
    that share a bucket across coroutines rely on asyncio's single-threaded
    cooperative scheduling for atomicity (no awaits inside ``try_consume``).
    """

    capacity: float
    refill_rate_per_second: float
    tokens: float = field(init=False)
    last_refill: float = field(init=False)

    def __post_init__(self) -> None:
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def try_consume(self, now: float | None = None) -> bool:
        if now is None:
            now = time.monotonic()
        elapsed = max(0.0, now - self.last_refill)
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.refill_rate_per_second,
        )
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RateLimiter:
    """Per-IP token bucket store.

    Each unique source IP gets its own bucket on first sight. Bucket
    parameters (capacity == requests_per_minute, refill == capacity / 60s)
    are uniform across IPs; per-route overrides land in Phase 7.
    """

    def __init__(self, requests_per_minute: int) -> None:
        if requests_per_minute <= 0:
            raise ValueError("requests_per_minute must be positive")
        self.requests_per_minute = requests_per_minute
        self._capacity = float(requests_per_minute)
        self._refill_per_second = requests_per_minute / 60.0
        self._buckets: dict[str, TokenBucket] = {}

    def allow(self, ip: str) -> bool:
        bucket = self._buckets.get(ip)
        if bucket is None:
            bucket = TokenBucket(
                capacity=self._capacity,
                refill_rate_per_second=self._refill_per_second,
            )
            self._buckets[ip] = bucket
        return bucket.try_consume()
