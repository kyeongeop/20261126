"""SQLite connection management and schema definition.

The schema is intentionally explicit (no ORM) so the preservation
guarantees are easy to audit: :data:`SCHEMA_SQL` creates append-mostly
``source_records`` plus derived ``timeline_events`` that always reference
the immutable originals through ``timeline_event_records``.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS incidents (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'medium',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
    code         TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    reliability  REAL NOT NULL DEFAULT 0.8 CHECK (reliability BETWEEN 0 AND 1),
    created_at   TEXT NOT NULL
);

-- Immutable raw records ingested from source systems.
-- Merge / split / unknown decisions never update or delete rows here.
CREATE TABLE IF NOT EXISTS source_records (
    id              TEXT PRIMARY KEY,
    source_code     TEXT NOT NULL REFERENCES sources(code),
    external_id     TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    occurred_at     TEXT NOT NULL,          -- normalized UTC ISO-8601
    occurred_at_raw TEXT,                   -- original timestamp string
    ingested_at     TEXT NOT NULL,
    payload_json    TEXT NOT NULL,
    UNIQUE (source_code, external_id)
);
CREATE INDEX IF NOT EXISTS idx_records_lookup
    ON source_records (user_id, event_type, occurred_at);

CREATE TABLE IF NOT EXISTS merge_candidates (
    id                   TEXT PRIMARY KEY,
    incident_id          TEXT REFERENCES incidents(id),
    status               TEXT NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending', 'merged', 'split', 'unknown')),
    confidence_score     REAL NOT NULL DEFAULT 0,
    confidence_label     TEXT NOT NULL DEFAULT 'low',
    confidence_json      TEXT NOT NULL DEFAULT '{}',
    time_delta_seconds   REAL,
    created_at           TEXT NOT NULL,
    resolved_at          TEXT,
    resolved_by          TEXT,
    resolution_note      TEXT,
    resolution_json      TEXT,
    canonical_event_id   TEXT
);
CREATE INDEX IF NOT EXISTS idx_candidates_status ON merge_candidates(status);

CREATE TABLE IF NOT EXISTS candidate_records (
    candidate_id TEXT NOT NULL REFERENCES merge_candidates(id),
    record_id    TEXT NOT NULL REFERENCES source_records(id),
    position     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (candidate_id, record_id)
);

-- Canonical timeline entries produced by an analyst resolution.
CREATE TABLE IF NOT EXISTS timeline_events (
    id                    TEXT PRIMARY KEY,
    incident_id           TEXT REFERENCES incidents(id),
    event_type            TEXT NOT NULL,
    user_id               TEXT NOT NULL,
    title                 TEXT NOT NULL,
    event_time            TEXT NOT NULL,
    time_basis            TEXT,
    resolution            TEXT NOT NULL CHECK (resolution IN ('merged', 'split', 'single')),
    candidate_id          TEXT,
    canonical_fields_json TEXT NOT NULL DEFAULT '{}',
    field_sources_json    TEXT NOT NULL DEFAULT '{}',
    created_at            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_timeline_time ON timeline_events (incident_id, event_time);

-- Traceability link: every timeline event points at all raw records it uses.
CREATE TABLE IF NOT EXISTS timeline_event_records (
    event_id  TEXT NOT NULL REFERENCES timeline_events(id) ON DELETE CASCADE,
    record_id TEXT NOT NULL REFERENCES source_records(id),
    PRIMARY KEY (event_id, record_id)
);

CREATE TABLE IF NOT EXISTS review_actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id TEXT NOT NULL,
    action       TEXT NOT NULL,
    analyst      TEXT,
    detail_json  TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_candidate ON review_actions(candidate_id);
"""


def connect(database_path: str | Path) -> sqlite3.Connection:
    """Open a configured SQLite connection.

    A special path of ``":memory:"`` is supported, but callers must keep a
    single connection alive for the lifetime of the application because
    each new connection to ``:memory:`` gets an independent database.
    """

    if database_path != ":memory:":
        Path(database_path).expanduser().parent.mkdir(parents=True, exist_ok=True)

    # check_same_thread=False lets a shared :memory: connection serve the
    # FastAPI threadpool; per-request file connections remain independent.
    conn = sqlite3.connect(
        str(database_path), timeout=30, check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if database_path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create all tables and indexes if they do not yet exist."""

    conn.executescript(SCHEMA_SQL)
    conn.commit()


def init_database_file(database_path: str | Path) -> None:
    """Convenience helper used by the CLI entry point."""

    conn = connect(database_path)
    try:
        init_db(conn)
    finally:
        conn.close()


def get_connection(database_path: Optional[str | Path] = None) -> sqlite3.Connection:
    """Return an initialised connection using ``database_path`` or config."""

    if database_path is None:
        from .config import DATABASE_PATH

        database_path = DATABASE_PATH
    conn = connect(database_path)
    init_db(conn)
    return conn
