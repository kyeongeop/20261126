"""把查询结果序列化为可导出的 CSV / JSON。"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

CSV_COLUMNS = [
    ("id", "ID"),
    ("ts", "时间(UTC)"),
    ("host", "主机"),
    ("service", "服务"),
    ("level", "级别"),
    ("message", "事件"),
    ("tags", "证据标签"),
    ("evidence", "证据"),
]


def _evidence_text(item: dict[str, Any]) -> str:
    parts = []
    for ev in item.get("evidence", []):
        ref = f" -> {ev['ref']}" if ev.get("ref") else ""
        parts.append(f"[{ev['kind']}] {ev['label']}{ref}")
    return " | ".join(parts)


def _sanitize_cell(value: Any) -> Any:
    """防止 Excel/WPS 把以 = + - @ 开头的单元格当公式执行。"""
    if not isinstance(value, str) or not value:
        return value
    if value[0] in ("=", "+", "-", "@") or value[:1] in ("\t", "\r"):
        return "'" + value
    return value


def to_csv(items: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    # utf-8-sig BOM 由响应编码阶段添加，保证 Excel 正确识别中文
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL)
    writer.writerow([header for _, header in CSV_COLUMNS])
    for item in items:
        row = []
        for key, _ in CSV_COLUMNS:
            if key == "tags":
                row.append(";".join(item.get("tags", [])))
            elif key == "evidence":
                row.append(_evidence_text(item))
            else:
                row.append(_sanitize_cell(item.get(key, "")))
        writer.writerow(row)
    return buffer.getvalue()


def to_json(items: list[dict[str, Any]]) -> str:
    return json.dumps(items, ensure_ascii=False, indent=2)
