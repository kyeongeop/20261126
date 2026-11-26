"""SQLite persistence for incidents, events, evidence links and users."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'investigator', 'viewer')),
    api_token TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    occurred_at TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS evidence_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    locator_kind TEXT NOT NULL
        CHECK (locator_kind IN ('line', 'offset', 'hash')),
    file_path TEXT NOT NULL,
    line_no INTEGER,
    end_line INTEGER,
    byte_offset INTEGER,
    byte_length INTEGER,
    content_hash TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_incident ON events(incident_id);
CREATE INDEX IF NOT EXISTS idx_evidence_event ON evidence_links(event_id);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize(db_path: Path) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


@contextmanager
def session(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = connect(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# --- seed data -----------------------------------------------------------

DEFAULT_USERS = [
    ("alice", "admin", "token-admin-alice"),
    ("bob", "investigator", "token-investigator-bob"),
    ("carol", "viewer", "token-viewer-carol"),
]


def seed_users(db_path: Path) -> None:
    with session(db_path) as conn:
        existing = {
            row["username"] for row in conn.execute("SELECT username FROM users")
        }
        for username, role, token in DEFAULT_USERS:
            if username not in existing:
                conn.execute(
                    "INSERT INTO users (username, role, api_token) "
                    "VALUES (?, ?, ?)",
                    (username, role, token),
                )


def get_user_by_token(db_path: Path, token: str) -> Optional[sqlite3.Row]:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, username, role, api_token FROM users "
            "WHERE api_token = ?",
            (token,),
        ).fetchone()
        return row
