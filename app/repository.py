"""时间线仓储：TQL 执行、经典筛选、分页上限与导出数据装配。"""

from __future__ import annotations

import sqlite3
import time
from typing import Any

from .tql import TQLError, compile_query, parse
from .tql.compiler import parse_time_value

DEFAULT_LIMIT = 100
MAX_LIMIT = 500
EXPORT_DEFAULT_LIMIT = 1000
EXPORT_MAX_LIMIT = 5000


class LimitError(ValueError):
    """limit/offset 参数非法。"""


def normalize_limit(
    raw: int | None, *, default: int, maximum: int
) -> tuple[int, bool]:
    """返回 (生效 limit, 是否被截断到上限)。"""
    if raw is None:
        return default, False
    if raw < 1:
        raise LimitError("limit 必须是 >= 1 的整数")
    if raw > maximum:
        return maximum, True
    return raw, False


class TimelineRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # -- TQL 查询 --------------------------------------------------------
    def search_tql(
        self,
        query: str = "",
        *,
        now: float | None = None,
        limit: int | None = DEFAULT_LIMIT,
        offset: int = 0,
        order: str = "asc",
        max_limit: int = MAX_LIMIT,
    ) -> dict[str, Any]:
        now = time.time() if now is None else now
        effective_limit, clamped = normalize_limit(
            limit, default=DEFAULT_LIMIT, maximum=max_limit
        )
        if offset < 0:
            raise LimitError("offset 不能为负数")
        if order.lower() not in ("asc", "desc"):
            raise LimitError("order 只支持 asc 或 desc")
        order = order.lower()

        ast = parse(query or "")
        where_sql, params = compile_query(ast, now=now, source=query or "")

        total = int(
            self.conn.execute(
                f"SELECT COUNT(*) AS c FROM events e WHERE {where_sql}", params
            ).fetchone()["c"]
        )

        rows = self.conn.execute(
            f"""
            SELECT e.id, e.epoch, e.ts, e.host, e.service, e.level, e.message,
                   GROUP_CONCAT(t.tag, '|') AS tag_list
            FROM events e
            LEFT JOIN event_tags t ON t.event_id = e.id
            WHERE {where_sql}
            GROUP BY e.id
            ORDER BY e.epoch {order.upper()}, e.id {order.upper()}
            LIMIT ? OFFSET ?
            """,
            [*params, effective_limit, offset],
        ).fetchall()

        items = [self._row_to_event(row) for row in rows]
        self._attach_evidence(items)
        returned = len(items)
        return {
            "query": query or "",
            "items": items,
            "total": total,
            "returned": returned,
            "limit": effective_limit,
            "offset": offset,
            "order": order,
            "truncated": offset + returned < total,
            "clamped": clamped,
            "max_limit": max_limit,
            "now_epoch": now,
        }

    # -- 经典筛选（主机 + 开始时间）------------------------------------
    def list_events(
        self,
        *,
        host: str | None = None,
        start: str | float | None = None,
        end: str | float | None = None,
        limit: int | None = DEFAULT_LIMIT,
        order: str = "asc",
    ) -> dict[str, Any]:
        clauses: list[str] = []
        params: list[Any] = []
        if host:
            clauses.append("e.host = ?")
            params.append(host)
        if start is not None and start != "":
            clauses.append("e.epoch >= ?")
            params.append(parse_time_value(start, None, None))
        if end is not None and end != "":
            clauses.append("e.epoch <= ?")
            params.append(parse_time_value(end, None, None))
        where = " AND ".join(clauses) if clauses else "1=1"

        effective_limit, clamped = normalize_limit(
            limit, default=DEFAULT_LIMIT, maximum=MAX_LIMIT
        )
        order = order.lower() if order.lower() in ("asc", "desc") else "asc"
        total = int(
            self.conn.execute(
                f"SELECT COUNT(*) AS c FROM events e WHERE {where}", params
            ).fetchone()["c"]
        )
        rows = self.conn.execute(
            f"""
            SELECT e.id, e.epoch, e.ts, e.host, e.service, e.level, e.message,
                   GROUP_CONCAT(t.tag, '|') AS tag_list
            FROM events e
            LEFT JOIN event_tags t ON t.event_id = e.id
            WHERE {where}
            GROUP BY e.id
            ORDER BY e.epoch {order.upper()}, e.id {order.upper()}
            LIMIT ?
            """,
            [*params, effective_limit],
        ).fetchall()
        items = [self._row_to_event(r) for r in rows]
        self._attach_evidence(items)
        return {
            "items": items,
            "total": total,
            "returned": len(items),
            "limit": effective_limit,
            "clamped": clamped,
            "max_limit": MAX_LIMIT,
        }

    # -- 元数据 ---------------------------------------------------------
    def list_hosts(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT host, COUNT(*) AS count FROM events GROUP BY host ORDER BY host"
        ).fetchall()
        return [{"host": r["host"], "count": r["count"]} for r in rows]

    def list_tags(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT tag, COUNT(*) AS count FROM event_tags "
            "GROUP BY tag ORDER BY count DESC, tag"
        ).fetchall()
        return [{"tag": r["tag"], "count": r["count"]} for r in rows]

    # -- 导出 -----------------------------------------------------------
    def export_rows(
        self,
        query: str = "",
        *,
        now: float | None = None,
        limit: int | None = EXPORT_DEFAULT_LIMIT,
        order: str = "asc",
    ) -> dict[str, Any]:
        result = self.search_tql(
            query,
            now=now,
            limit=limit,
            offset=0,
            order=order,
            max_limit=EXPORT_MAX_LIMIT,
        )
        return result

    # -- 装配 -----------------------------------------------------------
    def _row_to_event(self, row: sqlite3.Row) -> dict[str, Any]:
        tag_blob = row["tag_list"]
        tags = sorted({t for t in (tag_blob.split("|") if tag_blob else []) if t})
        return {
            "id": row["id"],
            "ts": row["ts"],
            "epoch": row["epoch"],
            "host": row["host"],
            "service": row["service"],
            "level": row["level"],
            "message": row["message"],
            "tags": tags,
            "evidence": [],
        }

    def _attach_evidence(self, items: list[dict[str, Any]]) -> None:
        if not items:
            return
        ids = [item["id"] for item in items]
        placeholders = ",".join("?" for _ in ids)
        rows = self.conn.execute(
            f"SELECT id, event_id, kind, label, ref FROM evidence "
            f"WHERE event_id IN ({placeholders}) ORDER BY id",
            ids,
        ).fetchall()
        by_event: dict[int, list[dict[str, Any]]] = {eid: [] for eid in ids}
        for r in rows:
            by_event.setdefault(r["event_id"], []).append(
                {"id": r["id"], "kind": r["kind"], "label": r["label"], "ref": r["ref"]}
            )
        for item in items:
            item["evidence"] = by_event.get(item["id"], [])


__all__ = [
    "TimelineRepository",
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "EXPORT_MAX_LIMIT",
    "TQLError",
]
