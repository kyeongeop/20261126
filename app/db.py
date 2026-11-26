from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL CHECK (length(trim(title)) > 0),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id),
    display_name TEXT NOT NULL CHECK (length(trim(display_name)) > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'voided')),
    current_version_number INTEGER NOT NULL CHECK (current_version_number >= 1),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);

CREATE TABLE IF NOT EXISTS evidence_versions (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    version_number INTEGER NOT NULL CHECK (version_number >= 1),
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    content_sha256 TEXT NOT NULL,
    version_digest TEXT NOT NULL,
    previous_version_digest TEXT,
    content BLOB NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    UNIQUE (evidence_id, version_number),
    UNIQUE (id, evidence_id)
);

CREATE INDEX IF NOT EXISTS idx_versions_evidence
    ON evidence_versions(evidence_id, version_number);

CREATE TABLE IF NOT EXISTS custody_events (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id),
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    action TEXT NOT NULL CHECK (
        action IN ('UPLOAD', 'VIEW', 'EXPORT', 'REPLACE', 'RENAME', 'DELETE')
    ),
    actor TEXT NOT NULL CHECK (length(trim(actor)) > 0),
    occurred_at TEXT NOT NULL,
    source TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    request_method TEXT NOT NULL,
    request_path TEXT NOT NULL,
    version_number INTEGER,
    version_id TEXT,
    version_digest TEXT,
    details TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    UNIQUE (evidence_id, sequence),
    UNIQUE (evidence_id, record_hash)
);

CREATE INDEX IF NOT EXISTS idx_custody_case_time
    ON custody_events(case_id, occurred_at, sequence);
CREATE INDEX IF NOT EXISTS idx_custody_evidence_sequence
    ON custody_events(evidence_id, sequence);

CREATE TRIGGER IF NOT EXISTS cases_no_delete
BEFORE DELETE ON cases
BEGIN
    SELECT RAISE(ABORT, 'case history cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS evidence_no_delete
BEFORE DELETE ON evidence
BEGIN
    SELECT RAISE(ABORT, 'evidence history cannot be deleted; mark it voided');
END;

CREATE TRIGGER IF NOT EXISTS evidence_void_is_terminal
BEFORE UPDATE OF status ON evidence
WHEN OLD.status = 'voided' AND NEW.status <> 'voided'
BEGIN
    SELECT RAISE(ABORT, 'voided evidence cannot be reactivated');
END;

CREATE TRIGGER IF NOT EXISTS evidence_version_monotonic
BEFORE UPDATE OF current_version_number ON evidence
WHEN NEW.current_version_number < OLD.current_version_number
BEGIN
    SELECT RAISE(ABORT, 'evidence version history cannot move backwards');
END;

CREATE TRIGGER IF NOT EXISTS versions_no_update
BEFORE UPDATE ON evidence_versions
BEGIN
    SELECT RAISE(ABORT, 'evidence versions are immutable');
END;

CREATE TRIGGER IF NOT EXISTS versions_no_delete
BEFORE DELETE ON evidence_versions
BEGIN
    SELECT RAISE(ABORT, 'evidence versions are immutable');
END;

CREATE TRIGGER IF NOT EXISTS custody_no_update
BEFORE UPDATE ON custody_events
BEGIN
    SELECT RAISE(ABORT, 'custody events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS custody_no_delete
BEFORE DELETE ON custody_events
BEGIN
    SELECT RAISE(ABORT, 'custody events are immutable');
END;
"""


def connect(database_path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        str(database_path),
        timeout=30,
        isolation_level=None,
        check_same_thread=False,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def initialize(database_path: str | Path) -> None:
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = connect(path)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(SCHEMA_SQL)
    finally:
        connection.close()


@contextmanager
def transaction(connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield connection
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()
