from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from antsilk import AntsilkConfig, AntsilkMiddleware
from antsilk.rules.rate_limit import RateLimiter, TokenBucket


def test_token_bucket_allows_up_to_capacity() -> None:
    bucket = TokenBucket(capacity=5.0, refill_rate_per_second=0.0)
    now = time.monotonic()
    for _ in range(5):
        assert bucket.try_consume(now=now) is True
    assert bucket.try_consume(now=now) is False


def test_token_bucket_refills_over_time() -> None:
    bucket = TokenBucket(capacity=5.0, refill_rate_per_second=1.0)
    now = time.monotonic()
    for _ in range(5):
        bucket.try_consume(now=now)
    assert bucket.try_consume(now=now) is False
    assert bucket.try_consume(now=now + 1.0) is True
    assert bucket.try_consume(now=now + 1.0) is False


def test_token_bucket_refill_caps_at_capacity() -> None:
    bucket = TokenBucket(capacity=5.0, refill_rate_per_second=10.0)
    now = time.monotonic()
    bucket.try_consume(now=now)
    # 100s later refill would add 1000 tokens but must cap at capacity.
    for _ in range(5):
        assert bucket.try_consume(now=now + 100.0) is True
    assert bucket.try_consume(now=now + 100.0) is False


def test_rate_limiter_isolates_buckets_per_ip() -> None:
    limiter = RateLimiter(requests_per_minute=2)
    assert limiter.allow("1.1.1.1") is True
    assert limiter.allow("1.1.1.1") is True
    assert limiter.allow("1.1.1.1") is False
    assert limiter.allow("2.2.2.2") is True
    assert limiter.allow("2.2.2.2") is True
    assert limiter.allow("2.2.2.2") is False


def test_rate_limiter_rejects_invalid_rate() -> None:
    with pytest.raises(ValueError):
        RateLimiter(requests_per_minute=0)
    with pytest.raises(ValueError):
        RateLimiter(requests_per_minute=-1)


def test_burst_of_100_requests_under_default_limit() -> None:
    """Plan Phase 2 step 4: hammer demo app with 100 reqs in 1s.

    With the default ``requests_per_minute=60`` and a sub-second sync loop,
    refill is negligible — expect ~60 successes and ~40 rate-limited.
    """
    app = FastAPI()
    app.add_middleware(
        AntsilkMiddleware,
        config=AntsilkConfig(threat_intel_enabled=False),
    )

    @app.get("/")
    async def root() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    start = time.monotonic()
    statuses = [client.get("/").status_code for _ in range(100)]
    elapsed = time.monotonic() - start

    successes = sum(1 for s in statuses if s == 200)
    blocked = sum(1 for s in statuses if s == 429)

    assert successes + blocked == 100
    # Refill during the burst is `elapsed * (60/60s) == elapsed` tokens.
    # Allow a generous margin around the expected ~60 successes.
    max_refill = int(elapsed) + 2
    assert 60 <= successes <= 60 + max_refill
    assert blocked >= 100 - (60 + max_refill)
