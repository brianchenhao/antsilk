from __future__ import annotations

from antsilk.events import Event
from antsilk.sinks.base import EventSink


def test_event_now_sets_iso_8601_utc_timestamp() -> None:
    event = Event.now(
        ip_address="10.0.0.1",
        method="GET",
        path="/api",
        rule_triggered="sqli",
        severity="high",
        response_code=403,
    )
    assert event.ip_address == "10.0.0.1"
    assert event.rule_triggered == "sqli"
    assert event.timestamp.endswith("+00:00")  # ISO 8601 UTC


def test_event_now_defaults_event_data_to_empty_dict() -> None:
    event = Event.now(
        ip_address="10.0.0.1",
        method="GET",
        path="/api",
        rule_triggered="rate_limit",
        severity="low",
        response_code=429,
    )
    assert event.event_data == {}
    assert event.user_agent is None
    assert event.app_id is None


def test_event_now_carries_arbitrary_event_data() -> None:
    event = Event.now(
        ip_address="1.2.3.4",
        method="POST",
        path="/upload",
        rule_triggered="threat_intel",
        severity="high",
        response_code=403,
        event_data={"feed": "firehol_level1"},
    )
    assert event.event_data == {"feed": "firehol_level1"}


def test_event_sink_protocol_runtime_check() -> None:
    """Anything with the right shape satisfies the Protocol."""

    class Dummy:
        def write(self, event: Event) -> None:
            del event

    assert isinstance(Dummy(), EventSink)


def test_event_sink_protocol_rejects_missing_write() -> None:
    class NotASink:
        pass

    assert not isinstance(NotASink(), EventSink)
