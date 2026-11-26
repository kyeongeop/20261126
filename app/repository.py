"""Data-access helpers built on top of SQLite connections."""

from __future__ import annotations

import sqlite3

from .hashing import shorten
from .locators import StoredLocator


def create_incident(conn: sqlite3.Connection, title: str,
                    username: str) -> sqlite3.Row:
    cur = conn.execute(
        "INSERT INTO incidents (title, created_by) VALUES (?, ?)",
        (title, username),
    )
    return conn.execute(
        "SELECT * FROM incidents WHERE id = ?", (cur.lastrowid,)
    ).fetchone()


def list_incidents(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM incidents ORDER BY id DESC"
    ).fetchall())


def get_incident(conn: sqlite3.Connection,
                 incident_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM incidents WHERE id = ?", (incident_id,)
    ).fetchone()


def create_event(conn: sqlite3.Connection, incident_id: int,
                 occurred_at: str, summary: str,
                 username: str) -> sqlite3.Row:
    cur = conn.execute(
        "INSERT INTO events (incident_id, occurred_at, summary, created_by) "
        "VALUES (?, ?, ?, ?)",
        (incident_id, occurred_at, summary, username),
    )
    return conn.execute(
        "SELECT * FROM events WHERE id = ?", (cur.lastrowid,)
    ).fetchone()


def list_events(conn: sqlite3.Connection,
                incident_id: int) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM events WHERE incident_id = ? ORDER BY occurred_at, id",
        (incident_id,),
    ).fetchall())


def get_event(conn: sqlite3.Connection, event_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM events WHERE id = ?", (event_id,)
    ).fetchone()


def add_evidence(conn: sqlite3.Connection, event_id: int,
                 locator: StoredLocator, label: str,
                 username: str) -> sqlite3.Row:
    cur = conn.execute(
        """
        INSERT INTO evidence_links (
            event_id, locator_kind, file_path, line_no, end_line,
            byte_offset, byte_length, content_hash, file_hash,
            label, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id, locator.kind.value, locator.file_path,
            locator.line, locator.end_line,
            locator.offset, locator.length,
            locator.content_hash, locator.file_hash,
            label, username,
        ),
    )
    return conn.execute(
        "SELECT * FROM evidence_links WHERE id = ?", (cur.lastrowid,)
    ).fetchone()


def list_evidence_for_event(conn: sqlite3.Connection,
                            event_id: int) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM evidence_links WHERE event_id = ? ORDER BY id",
        (event_id,),
    ).fetchall())


def get_evidence(conn: sqlite3.Connection,
                 evidence_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM evidence_links WHERE id = ?", (evidence_id,)
    ).fetchone()


def delete_evidence(conn: sqlite3.Connection, evidence_id: int) -> bool:
    cur = conn.execute(
        "DELETE FROM evidence_links WHERE id = ?", (evidence_id,)
    )
    return cur.rowcount > 0


def evidence_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "event_id": row["event_id"],
        "locator_kind": row["locator_kind"],
        "file_path": row["file_path"],
        "line_no": row["line_no"],
        "end_line": row["end_line"],
        "byte_offset": row["byte_offset"],
        "byte_length": row["byte_length"],
        "content_hash": row["content_hash"],
        "file_hash": row["file_hash"],
        "content_hash_prefix": shorten(row["content_hash"]),
        "file_hash_prefix": shorten(row["file_hash"]),
        "label": row["label"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }
