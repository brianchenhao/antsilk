from __future__ import annotations

import json
import threading
from dataclasses import asdict
from pathlib import Path

from antsilk.events import Event


class JSONLinesSink:
    """Append-only sink that writes one JSON object per line.

    Suited for tail-friendly logging pipelines (Vector, Filebeat,
    Promtail). A single in-process lock serialises writers — POSIX
    O_APPEND would suffice for short lines, but the lock is explicit
    so behaviour is identical on Windows.
    """

    def __init__(self, path: str | Path = "antsilk_events.jsonl") -> None:
        self.path = str(path)
        self._lock = threading.Lock()

    def write(self, event: Event) -> None:
        line = json.dumps(asdict(event)) + "\n"
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)
