from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from antsilk.events import Event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    ip_address      TEXT    NOT NULL,
    method          TEXT    NOT NULL,
    path            TEXT    NOT NULL,
    rule_triggered  TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    response_code   INTEGER NOT NULL,
    user_agent      TEXT,
    app_id          TEXT,
    event_data      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip        ON events(ip_address);
CREATE INDEX IF NOT EXISTS idx_events_rule      ON events(rule_triggered);
"""


class SQLiteSink:
    """Default sink — writes events to a local SQLite file in WAL mode.

    Each ``write()`` opens a short-lived connection, INSERTs, commits,
    and closes. WAL mode is a per-database setting persisted in the
    file; setting it on every connection is idempotent and ensures
    concurrent readers (a future stats dashboard) never block writes.
    """

    def __init__(self, path: str | Path = "antsilk_events.db") -> None:
        self.path = str(path)
        self._init_lock = threading.Lock()
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _initialize(self) -> None:
        if self._initialized:
            return
        with self._init_lock:
            if self._initialized:
                return
            conn = self._connect()
            try:
                conn.executescript(_SCHEMA)
                conn.commit()
            finally:
                conn.close()
            self._initialized = True

    def write(self, event: Event) -> None:
        self._initialize()
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO events"
                " (timestamp, ip_address, method, path, rule_triggered,"
                "  severity, response_code, user_agent, app_id, event_data)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.timestamp,
                    event.ip_address,
                    event.method,
                    event.path,
                    event.rule_triggered,
                    event.severity,
                    event.response_code,
                    event.user_agent,
                    event.app_id,
                    json.dumps(event.event_data),
                ),
            )
            conn.commit()
        finally:
            conn.close()
