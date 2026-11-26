"""SQLite storage for incidents, timeline events, and redaction rules."""

from __future__ import annotations

import json
import secrets
import sqlite3
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    occurred_at TEXT NOT NULL,
    actor TEXT,
    payload TEXT NOT NULL,
    UNIQUE (incident_id, occurred_at, payload)
);
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    spec TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
);
"""


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def get_secret(self) -> bytes:
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key = 'redaction_secret'"
        ).fetchone()
        if row:
            return bytes.fromhex(row["value"])
        secret = secrets.token_hex(32)
        self._conn.execute(
            "INSERT INTO settings (key, value) VALUES ('redaction_secret', ?)",
            (secret,),
        )
        self._conn.commit()
        return bytes.fromhex(secret)

    def create_incident(self, title: str) -> int:
        cur = self._conn.execute(
            "INSERT INTO incidents (title) VALUES (?)", (title,)
        )
        self._conn.commit()
        return cur.lastrowid

    def add_event(
        self, incident_id: int, occurred_at: str, actor: str | None, payload: dict
    ) -> int:
        cur = self._conn.execute(
            "INSERT OR IGNORE INTO events (incident_id, occurred_at, actor, payload)"
            " VALUES (?, ?, ?, ?)",
            (incident_id, occurred_at, actor, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()
        if cur.rowcount:
            return cur.lastrowid
        row = self._conn.execute(
            "SELECT id FROM events WHERE incident_id = ? AND occurred_at = ? AND payload = ?",
            (incident_id, occurred_at, json.dumps(payload, sort_keys=True)),
        ).fetchone()
        return row["id"]

    def get_event(self, event_id: int) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM events WHERE id = ?", (event_id,)
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "incident_id": row["incident_id"],
            "occurred_at": row["occurred_at"],
            "actor": row["actor"],
            "payload": json.loads(row["payload"]),
        }

    def list_events(self, incident_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id FROM events WHERE incident_id = ? ORDER BY occurred_at, id",
            (incident_id,),
        ).fetchall()
        return [self.get_event(row["id"]) for row in rows]

    def upsert_rule(self, name: str, spec: dict, enabled: bool = True) -> None:
        self._conn.execute(
            "INSERT INTO rules (name, spec, enabled) VALUES (?, ?, ?)"
            " ON CONFLICT(name) DO UPDATE SET spec = excluded.spec,"
            " enabled = excluded.enabled",
            (name, json.dumps(spec), int(enabled)),
        )
        self._conn.commit()

    def list_rules(self, enabled_only: bool = True) -> list[dict[str, Any]]:
        query = "SELECT name, spec, enabled FROM rules"
        if enabled_only:
            query += " WHERE enabled = 1"
        rows = self._conn.execute(query + " ORDER BY name").fetchall()
        return [
            {"name": r["name"], "spec": json.loads(r["spec"]), "enabled": bool(r["enabled"])}
            for r in rows
        ]
