"""Snapshot antsilk_events.db into a static JSON file the React site bundles.

The landing page is fully static (served as plain HTML/JS by Hostinger),
so the "attack counter" cannot query the DB at runtime. Instead, this
script reads geyam's local SQLite ledger and writes an aggregate file at
src/data/attack_stats.json. The JSON is committed and refreshed on a
cadence (manually for now; can wire into CI later).

Usage:

    python scripts/build_stats.py
    python scripts/build_stats.py --db path/to/antsilk_events.db
    python scripts/build_stats.py --db path/to/events.db --out custom.json

If the DB does not exist, a zeroed stats file is emitted. The site then
renders "0 blocked" rather than crashing the build.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

RULES = ("threat_intel", "rate_limit", "sqli", "xss", "path_traversal", "bad_header", "bad_token")


def aggregate(db_path: Path) -> dict[str, object]:
    if not db_path.exists():
        return _empty()
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.OperationalError:
        return _empty()
    try:
        cur = conn.cursor()
        try:
            cur.execute("SELECT COUNT(*) FROM events")
        except sqlite3.OperationalError:
            return _empty()
        total = int(cur.fetchone()[0])
        cur.execute("SELECT rule_triggered, COUNT(*) FROM events GROUP BY rule_triggered")
        by_rule = {rule: 0 for rule in RULES}
        for rule, count in cur.fetchall():
            by_rule[rule] = int(count)
        cur.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events")
        first_seen, last_seen = cur.fetchone()
        cur.execute("SELECT COUNT(DISTINCT ip_address) FROM events")
        unique_ips = int(cur.fetchone()[0])
    finally:
        conn.close()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_blocked": total,
        "unique_ips": unique_ips,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "by_rule": by_rule,
    }


def _empty() -> dict[str, object]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_blocked": 0,
        "unique_ips": 0,
        "first_seen": None,
        "last_seen": None,
        "by_rule": {rule: 0 for rule in RULES},
    }


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent.parent
    default_db = (here.parent / "antsilk_events.db").resolve()
    default_out = (here / "src" / "data" / "attack_stats.json").resolve()

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=default_db, help="path to antsilk_events.db")
    parser.add_argument("--out", type=Path, default=default_out, help="output JSON path")
    args = parser.parse_args(argv)

    stats = aggregate(args.db.resolve())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({stats['total_blocked']} events from {args.db})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
