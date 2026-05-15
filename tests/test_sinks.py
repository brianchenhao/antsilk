from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from antsilk import (
    AntsilkConfig,
    AntsilkMiddleware,
    Event,
    EventSink,
    JSONLinesSink,
    RemoteSink,
    SQLiteSink,
)
from antsilk.rules.threat_intel import ThreatIntelManager


# ============================ Event dataclass ===========================

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


# ========================== EventSink Protocol ==========================

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


# ============================== SQLiteSink ==============================

def _sample_event(**overrides: Any) -> Event:
    base = dict(
        ip_address="10.0.0.1",
        method="GET",
        path="/api/users",
        rule_triggered="sqli",
        severity="high",
        response_code=403,
        user_agent="Mozilla/5.0",
        event_data={"matched": "OR 1=1"},
    )
    base.update(overrides)
    return Event.now(**base)


def test_sqlite_sink_creates_db_file_on_first_write(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    assert not db.exists()
    sink = SQLiteSink(db)
    # Construction alone must not touch the filesystem — the file is the
    # signal an adopter sees on first block, per plan Flow 4.
    assert not db.exists()
    sink.write(_sample_event())
    assert db.exists()


def test_sqlite_sink_inserts_row_with_expected_columns(tmp_path: Path) -> None:
    sink = SQLiteSink(tmp_path / "events.db")
    sink.write(_sample_event())
    conn = sqlite3.connect(tmp_path / "events.db")
    try:
        row = conn.execute(
            "SELECT ip_address, method, path, rule_triggered, severity,"
            " response_code, user_agent, event_data FROM events"
        ).fetchone()
    finally:
        conn.close()
    assert row[:7] == (
        "10.0.0.1",
        "GET",
        "/api/users",
        "sqli",
        "high",
        403,
        "Mozilla/5.0",
    )
    assert json.loads(row[7]) == {"matched": "OR 1=1"}


def test_sqlite_sink_appends_multiple_events(tmp_path: Path) -> None:
    sink = SQLiteSink(tmp_path / "events.db")
    sink.write(_sample_event(ip_address="1.1.1.1"))
    sink.write(_sample_event(ip_address="2.2.2.2"))
    sink.write(_sample_event(ip_address="3.3.3.3"))
    conn = sqlite3.connect(tmp_path / "events.db")
    try:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        ips = [r[0] for r in conn.execute(
            "SELECT ip_address FROM events ORDER BY id"
        )]
    finally:
        conn.close()
    assert count == 3
    assert ips == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_sqlite_sink_enables_wal_mode(tmp_path: Path) -> None:
    """Plan: WAL reduces write-lock contention from concurrent writers."""
    sink = SQLiteSink(tmp_path / "events.db")
    sink.write(_sample_event())
    conn = sqlite3.connect(tmp_path / "events.db")
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        conn.close()
    assert mode.lower() == "wal"


def test_sqlite_sink_creates_expected_indexes(tmp_path: Path) -> None:
    sink = SQLiteSink(tmp_path / "events.db")
    sink.write(_sample_event())
    conn = sqlite3.connect(tmp_path / "events.db")
    try:
        names = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
        }
    finally:
        conn.close()
    assert {"idx_events_timestamp", "idx_events_ip", "idx_events_rule"} <= names


# ============================== JSONLinesSink ===========================

def test_jsonlines_sink_writes_one_object_per_line(tmp_path: Path) -> None:
    jsonl = tmp_path / "events.jsonl"
    sink = JSONLinesSink(jsonl)
    sink.write(_sample_event(ip_address="1.1.1.1"))
    sink.write(_sample_event(ip_address="2.2.2.2"))
    lines = jsonl.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert [p["ip_address"] for p in parsed] == ["1.1.1.1", "2.2.2.2"]


def test_jsonlines_sink_round_trip_preserves_event_data(tmp_path: Path) -> None:
    sink = JSONLinesSink(tmp_path / "events.jsonl")
    sink.write(
        _sample_event(
            rule_triggered="xss",
            event_data={"matched": "<script>", "ctx": "header"},
        )
    )
    line = (tmp_path / "events.jsonl").read_text(encoding="utf-8").strip()
    obj = json.loads(line)
    assert obj["rule_triggered"] == "xss"
    assert obj["event_data"] == {"matched": "<script>", "ctx": "header"}


def test_jsonlines_sink_appends_to_existing_file(tmp_path: Path) -> None:
    jsonl = tmp_path / "events.jsonl"
    jsonl.write_text('{"existing": true}\n', encoding="utf-8")
    JSONLinesSink(jsonl).write(_sample_event())
    lines = jsonl.read_text(encoding="utf-8").splitlines()
    assert lines[0] == '{"existing": true}'
    assert json.loads(lines[1])["ip_address"] == "10.0.0.1"


# =============================== RemoteSink =============================

def test_remote_sink_construction_does_not_raise() -> None:
    sink = RemoteSink("https://api.antsilk.com/events", api_key="x")
    assert sink.endpoint == "https://api.antsilk.com/events"
    assert sink.api_key == "x"


def test_remote_sink_write_raises_not_implemented_error() -> None:
    sink = RemoteSink("https://api.antsilk.com/events")
    with pytest.raises(NotImplementedError) as exc:
        sink.write(_sample_event())
    # Friendly message must point adopters at the alternative sinks.
    msg = str(exc.value)
    assert "v0.5" in msg
    assert "SQLiteSink" in msg or "JSONLinesSink" in msg


# ===================== Phase 6.5: middleware wiring =====================

def _drive(
    mw: AntsilkMiddleware,
    *,
    client_ip: str = "203.0.113.7",
    path: str = "/",
    query: bytes = b"",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> int:
    """Run a single GET through the middleware directly via ASGI."""

    if headers is None:
        headers = [(b"user-agent", b"Mozilla/5.0")]

    async def inner(scope, receive, send):  # type: ignore[no-untyped-def]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    # The middleware's inner app is `mw.app`; replace it for this drive.
    mw.app = inner

    async def recv():  # type: ignore[no-untyped-def]
        return {"type": "http.request", "body": b"", "more_body": False}

    statuses: list[int] = []

    async def send(msg):  # type: ignore[no-untyped-def]
        if msg["type"] == "http.response.start":
            statuses.append(msg["status"])

    scope = {
        "type": "http",
        "client": (client_ip, 0),
        "method": "GET",
        "path": path,
        "query_string": query,
        "headers": headers,
    }
    asyncio.run(mw(scope, recv, send))
    return statuses[0]


def _read_db(path: Path) -> list[dict[str, Any]]:
    conn = sqlite3.connect(path)
    try:
        rows = list(
            conn.execute(
                "SELECT ip_address, method, path, rule_triggered, severity,"
                " response_code, user_agent, event_data FROM events"
                " ORDER BY id"
            )
        )
    finally:
        conn.close()
    keys = (
        "ip_address",
        "method",
        "path",
        "rule_triggered",
        "severity",
        "response_code",
        "user_agent",
        "event_data",
    )
    return [
        {**dict(zip(keys, row)), "event_data": json.loads(row[7])} for row in rows
    ]


def test_middleware_writes_event_on_threat_intel_block(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    sink = SQLiteSink(db)
    mw = AntsilkMiddleware(
        app=lambda *_a, **_kw: None,  # replaced inside _drive
        config=AntsilkConfig(sink=sink),
    )
    assert mw._threat_intel is not None
    mw._threat_intel.populate([(int.from_bytes(bytes([127, 0, 0, 1]), "big"),
                                int.from_bytes(bytes([127, 0, 0, 1]), "big"))])

    status = _drive(mw, client_ip="127.0.0.1")
    assert status == 403

    rows = _read_db(db)
    assert len(rows) == 1
    assert rows[0]["rule_triggered"] == "threat_intel"
    assert rows[0]["severity"] == "high"
    assert rows[0]["response_code"] == 403
    assert "feeds" in rows[0]["event_data"]


def test_middleware_writes_event_on_rate_limit_429(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    sink = SQLiteSink(db)
    mw = AntsilkMiddleware(
        app=lambda *_a, **_kw: None,
        config=AntsilkConfig(
            requests_per_minute=1,
            threat_intel_enabled=False,
            sink=sink,
        ),
    )
    assert _drive(mw, client_ip="9.9.9.9") == 200
    assert _drive(mw, client_ip="9.9.9.9") == 429

    rows = _read_db(db)
    assert len(rows) == 1
    assert rows[0]["rule_triggered"] == "rate_limit"
    assert rows[0]["severity"] == "low"
    assert rows[0]["response_code"] == 429
    assert rows[0]["event_data"] == {"requests_per_minute": 1}


def test_middleware_writes_event_on_bad_header_block(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    sink = SQLiteSink(db)
    mw = AntsilkMiddleware(
        app=lambda *_a, **_kw: None,
        config=AntsilkConfig(threat_intel_enabled=False, sink=sink),
    )
    status = _drive(mw, headers=[])  # missing UA
    assert status == 403
    rows = _read_db(db)
    assert len(rows) == 1
    assert rows[0]["rule_triggered"] == "bad_header"
    assert rows[0]["severity"] == "medium"
    assert rows[0]["event_data"] == {"subrule": "missing_user_agent"}


def test_middleware_writes_event_on_pattern_match(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    sink = SQLiteSink(db)
    mw = AntsilkMiddleware(
        app=lambda *_a, **_kw: None,
        config=AntsilkConfig(threat_intel_enabled=False, sink=sink),
    )
    status = _drive(mw, query=b"id=1 OR 1=1")
    assert status == 403
    rows = _read_db(db)
    assert len(rows) == 1
    assert rows[0]["rule_triggered"] == "sqli"
    assert rows[0]["severity"] == "high"
    assert "matched" in rows[0]["event_data"]


def test_middleware_does_not_emit_event_on_allowed_request(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    sink = SQLiteSink(db)
    mw = AntsilkMiddleware(
        app=lambda *_a, **_kw: None,
        config=AntsilkConfig(threat_intel_enabled=False, sink=sink),
    )
    assert _drive(mw) == 200
    # Default SQLiteSink is lazy — no write means no file.
    assert not db.exists()


def test_middleware_sink_failure_does_not_propagate(tmp_path: Path) -> None:
    """A broken sink must not turn into a 500 for the adopter's app."""

    class BrokenSink:
        def write(self, event: Event) -> None:
            del event
            raise RuntimeError("disk full")

    mw = AntsilkMiddleware(
        app=lambda *_a, **_kw: None,
        config=AntsilkConfig(
            requests_per_minute=1,
            threat_intel_enabled=False,
            sink=BrokenSink(),
        ),
    )
    assert _drive(mw) == 200
    # Even though the sink raises, the 429 still goes out cleanly.
    assert _drive(mw) == 429


# ================ Phase 6.6: sink swap (no DB created) ==================

def test_middleware_with_jsonlines_sink_creates_no_db_file(
    tmp_path: Path,
) -> None:
    """Plan Phase 6.6: pass JSONLinesSink, verify DB never created."""
    jsonl = tmp_path / "events.jsonl"
    mw = AntsilkMiddleware(
        app=lambda *_a, **_kw: None,
        config=AntsilkConfig(
            requests_per_minute=1,
            threat_intel_enabled=False,
            sink=JSONLinesSink(jsonl),
        ),
    )
    assert _drive(mw, client_ip="4.4.4.4") == 200
    assert _drive(mw, client_ip="4.4.4.4") == 429

    # JSONL was written and contains the rate-limit event.
    assert jsonl.exists()
    lines = jsonl.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["rule_triggered"] == "rate_limit"

    # No SQLite artefacts anywhere in tmp_path — the default sink was
    # never constructed because the adopter supplied an explicit one.
    for suffix in (".db", ".db-wal", ".db-shm"):
        assert list(tmp_path.glob(f"*{suffix}")) == []
