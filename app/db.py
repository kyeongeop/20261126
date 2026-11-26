"""SQLite 连接与表结构。仅使用标准库 sqlite3。"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY,
    epoch   REAL    NOT NULL,
    ts      TEXT    NOT NULL,
    host    TEXT    NOT NULL,
    service TEXT    NOT NULL,
    level   TEXT    NOT NULL,
    message TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_epoch ON events(epoch);
CREATE INDEX IF NOT EXISTS idx_events_host  ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_level ON events(level);

CREATE TABLE IF NOT EXISTS event_tags (
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    tag      TEXT    NOT NULL,
    PRIMARY KEY (event_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_event_tags_tag ON event_tags(tag);

CREATE TABLE IF NOT EXISTS evidence (
    id       INTEGER PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    kind     TEXT    NOT NULL,   -- log | metric | trace | link | note
    label    TEXT    NOT NULL,
    ref      TEXT
);
CREATE INDEX IF NOT EXISTS idx_evidence_event ON evidence(event_id);
"""


def connect(db_path: str | Path = ":memory:") -> sqlite3.Connection:
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(db_path),
        check_same_thread=False,
        detect_types=sqlite3.PARSE_DECLTYPES,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def is_empty(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
    return int(row["c"]) == 0
