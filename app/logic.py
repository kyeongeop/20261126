"""Pure, framework-free conflict analysis logic.

This module has no database or FastAPI dependencies, which makes the
time comparison, field diff and confidence scoring trivial to unit test.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return to_utc_iso(utc_now())


def parse_dt(value: datetime | str) -> datetime:
    """Parse ISO-8601 values (accepting trailing ``Z``) into aware UTC.

    Naive datetimes / strings are assumed to be UTC, matching log exports
    that omit offsets.
    """

    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_utc_iso(value: datetime | str) -> str:
    dt = parse_dt(value)
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def human_delta(seconds: float) -> str:
    """Render an absolute number of seconds as concise Chinese text."""

    total = max(0, int(round(abs(seconds))))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)

    parts: list[str] = []
    if days:
        parts.append(f"{days}天")
    if hours:
        parts.append(f"{hours}小时")
    if minutes and days == 0:
        parts.append(f"{minutes}分")
    if secs and not days and hours == 0:
        parts.append(f"{secs}秒")
    if not parts:
        return "0秒"
    return "".join(parts[:2])


# ---------------------------------------------------------------------------
# Field metadata / normalisation
# ---------------------------------------------------------------------------

FIELD_LABELS: dict[str, str] = {
    "occurred_at": "事件时间",
    "user_id": "用户",
    "event_type": "事件类型",
    "result": "登录结果",
    "status": "状态",
    "ip_address": "来源 IP",
    "client_ip": "客户端 IP",
    "src_ip": "源 IP",
    "device_id": "设备 ID",
    "device_name": "设备名称",
    "session_id": "会话 ID",
    "user_agent": "User-Agent",
    "location": "地理位置",
    "city": "城市",
    "geo": "地理坐标",
    "asn": "ASN / 运营商",
    "mfa_method": "MFA 方式",
    "auth_method": "认证方式",
    "auth_provider": "身份提供方",
    "protocol": "协议",
    "app": "应用",
}

# Fields are rendered in this order when present; remaining fields follow
# alphabetically afterwards.
FIELD_ORDER: list[str] = [
    "occurred_at",
    "user_id",
    "event_type",
    "result",
    "status",
    "ip_address",
    "client_ip",
    "src_ip",
    "device_id",
    "device_name",
    "session_id",
    "user_agent",
    "location",
    "city",
    "geo",
    "asn",
    "auth_method",
    "mfa_method",
    "auth_provider",
    "protocol",
    "app",
]

# Weight used by the confidence scorer for corroborating attributes.
ATTR_WEIGHTS: dict[str, float] = {
    "ip_address": 0.12,
    "client_ip": 0.12,
    "src_ip": 0.12,
    "device_id": 0.1,
    "device_name": 0.05,
    "session_id": 0.06,
    "user_agent": 0.05,
    "location": 0.05,
    "city": 0.04,
    "geo": 0.04,
    "asn": 0.03,
    "mfa_method": 0.02,
    "auth_method": 0.02,
    "result": 0.02,
    "status": 0.02,
}


def field_label(key: str) -> str:
    return FIELD_LABELS.get(key, key)


def normalise_value(value: Any) -> str:
    """Normalise a value for equality checks only (display stays original)."""

    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    text = str(value).strip()
    # Collapse whitespace and compare case-insensitively.
    text = re.sub(r"\s+", " ", text)
    return text.casefold()


def display_value(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return str(value)


def ordered_field_names(names: Iterable[str]) -> list[str]:
    known = [name for name in FIELD_ORDER if name in set(names)]
    extras = sorted(name for name in names if name not in FIELD_ORDER)
    return known + extras


def extract_fields(
    *, event_type: str, user_id: str, occurred_at: str, payload: Mapping[str, Any]
) -> dict[str, Any]:
    """Merge core columns and the raw payload into one comparable field map."""

    fields: dict[str, Any] = dict(payload or {})
    # Core, normalised columns win over any duplicate payload key so the
    # comparison always reflects what was actually stored/indexed.
    fields["occurred_at"] = occurred_at
    fields["user_id"] = user_id
    fields["event_type"] = event_type
    return fields


def _view_fields(view: Mapping[str, Any]) -> dict[str, Any]:
    fields = view.get("fields")
    if isinstance(fields, dict):
        return fields
    return extract_fields(
        event_type=view["event_type"],
        user_id=view["user_id"],
        occurred_at=view["occurred_at"],
        payload=view.get("payload") or {},
    )


# ---------------------------------------------------------------------------
# Time comparison
# ---------------------------------------------------------------------------


def build_time_comparison(views: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Per-source times plus earliest/latest delta information."""

    entries: list[dict[str, Any]] = []
    parsed: list[tuple[datetime, Mapping[str, Any]]] = []
    for view in views:
        dt = parse_dt(view["occurred_at"])
        parsed.append((dt, view))

    if not parsed:
        return {"entries": [], "earliest": None, "latest": None,
                "delta_seconds": 0.0, "delta_human": "0秒"}

    earliest_dt = min(dt for dt, _ in parsed)
    latest_dt = max(dt for dt, _ in parsed)
    delta = (latest_dt - earliest_dt).total_seconds()

    for dt, view in sorted(parsed, key=lambda item: item[0]):
        offset = (dt - earliest_dt).total_seconds()
        entries.append(
            {
                "record_id": view["record_id"],
                "source_code": view.get("source_code"),
                "source_name": view.get("source_name") or view.get("source_code"),
                "reliability": view.get("reliability", 0.8),
                "occurred_at": to_utc_iso(dt),
                "occurred_at_raw": view.get("occurred_at_raw"),
                "offset_seconds": offset,
                "offset_human": ("最早" if offset == 0 else f"晚 {human_delta(offset)}"),
                "is_earliest": offset == 0,
            }
        )

    return {
        "entries": entries,
        "earliest": to_utc_iso(earliest_dt),
        "latest": to_utc_iso(latest_dt),
        "delta_seconds": delta,
        "delta_human": human_delta(delta),
    }


# ---------------------------------------------------------------------------
# Field-level diff
# ---------------------------------------------------------------------------


def build_field_diff(views: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return an ordered, per-field comparison across every source record."""

    all_names: set[str] = set()
    per_view_fields: list[dict[str, Any]] = []
    for view in views:
        fields = _view_fields(view)
        per_view_fields.append(fields)
        all_names.update(fields.keys())

    diff: list[dict[str, Any]] = []
    for name in ordered_field_names(all_names):
        values: list[dict[str, Any]] = []
        normalised_values: set[str] = set()
        provided = 0
        for view, fields in zip(views, per_view_fields):
            present = name in fields and fields[name] is not None
            raw_value = fields.get(name) if present else None
            if present:
                provided += 1
                normalised_values.add(normalise_value(raw_value))
            values.append(
                {
                    "record_id": view["record_id"],
                    "source_code": view.get("source_code"),
                    "source_name": view.get("source_name") or view.get("source_code"),
                    "value": raw_value if present else None,
                    "display": display_value(raw_value) if present else "未提供",
                    "present": present,
                }
            )

        conflict = provided >= 2 and len(normalised_values) > 1
        diff.append(
            {
                "field": name,
                "label": field_label(name),
                "type": "time" if name == "occurred_at" else "primitive",
                "conflict": conflict,
                "provided_count": provided,
                "distinct_count": len(normalised_values),
                "values": values,
            }
        )
    return diff


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------


def time_proximity_factor(delta_seconds: float) -> float:
    """Piecewise decay: closer timestamps strongly indicate the same event."""

    delta = abs(delta_seconds)
    if delta <= 60:
        return 1.0
    if delta <= 5 * 60:
        return 0.92
    if delta <= 15 * 60:
        return 0.75
    if delta <= 60 * 60:
        return 0.5
    if delta <= 6 * 3600:
        return 0.25
    if delta <= 24 * 3600:
        return 0.1
    return 0.0


def confidence_label(score: float) -> tuple[str, str]:
    if score >= 0.8:
        return "high", "高可信"
    if score >= 0.55:
        return "medium", "中可信"
    return "low", "低可信"


def score_match(views: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Explainable 0..1 confidence that the records describe one event.

    Buckets (weights sum to 1.0):
      * identity consistency (same user + event type): 0.20
      * timestamp proximity:                            0.45
      * corroborating attribute overlap:                 0.35
    """

    count = len(views)
    fields_list = [_view_fields(view) for view in views]

    # -- Identity ---------------------------------------------------------
    users = {normalise_value(view.get("user_id")) for view in views}
    types = {normalise_value(view.get("event_type")) for view in views}
    same_user = len(users) == 1 and "" not in users
    same_type = len(types) == 1 and "" not in types
    identity_score = (0.12 if same_user else 0.0) + (0.08 if same_type else 0.0)

    components: list[dict[str, Any]] = [
        {
            "key": "identity",
            "label": "主体与事件类型一致",
            "score": round(identity_score, 3),
            "max": 0.2,
            "detail": (
                "用户与事件类型均相同"
                if same_user and same_type
                else "存在用户或事件类型不一致"
            ),
        }
    ]

    # -- Time proximity --------------------------------------------------
    times = [parse_dt(view["occurred_at"]) for view in views]
    delta = (max(times) - min(times)).total_seconds() if times else 0.0
    factor = time_proximity_factor(delta)
    time_score = round(0.45 * factor, 3)
    components.append(
        {
            "key": "time",
            "label": "时间接近度",
            "score": time_score,
            "max": 0.45,
            "detail": f"各来源时间相差 {human_delta(delta)}",
        }
    )

    # -- Attribute overlap ----------------------------------------------
    candidate_fields: set[str] = set()
    for fields in fields_list:
        candidate_fields.update(k for k in fields if k not in {"occurred_at"})

    weight_total = 0.0
    weight_matched = 0.0
    findings: list[dict[str, Any]] = []
    for name in ordered_field_names(candidate_fields):
        weight = ATTR_WEIGHTS.get(name, 0.02)
        present_values: list[str] = []
        for fields in fields_list:
            if name in fields and fields[name] is not None:
                present_values.append(normalise_value(fields[name]))
        # Only compare fields reported by at least two sources.
        if len(present_values) < 2:
            continue
        weight_total += weight
        matched = len(set(present_values)) == 1
        if matched:
            weight_matched += weight
        findings.append(
            {
                "field": name,
                "label": field_label(name),
                "status": "match" if matched else "conflict",
                "weight": weight,
            }
        )

    if weight_total > 0:
        attr_factor = weight_matched / weight_total
        attr_detail = (
            f"{sum(1 for f in findings if f['status'] == 'match')}/"
            f"{len(findings)} 个可比较字段一致"
        )
    else:
        # No overlapping extension fields: neutral rather than punitive.
        attr_factor = 0.5
        attr_detail = "缺少可交叉验证的扩展字段"
    attr_score = round(0.35 * attr_factor, 3)
    components.append(
        {
            "key": "attributes",
            "label": "字段交叉印证",
            "score": attr_score,
            "max": 0.35,
            "detail": attr_detail,
        }
    )

    score = round(min(1.0, max(0.0, identity_score + time_score + attr_score)), 3)
    label, label_text = confidence_label(score)

    reliabilities = [float(view.get("reliability", 0.8)) for view in views] or [0.8]
    avg_reliability = round(sum(reliabilities) / len(reliabilities), 3)

    return {
        "score": score,
        "percent": round(score * 100),
        "label": label,
        "label_text": label_text,
        "trust_adjusted_score": round(score * avg_reliability, 3),
        "avg_source_reliability": avg_reliability,
        "time_delta_seconds": delta,
        "time_delta_human": human_delta(delta),
        "record_count": count,
        "components": components,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Canonical value selection
# ---------------------------------------------------------------------------


def choose_canonical_values(
    field_diff: Sequence[Mapping[str, Any]],
    views: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Pick a default canonical value per field.

    The value comes from the single most reliable source that reports that
    field. Returns ``(values, field_sources)`` where ``field_sources`` maps
    field name -> the chosen raw record id for provenance.
    """

    reliability_by_record = {
        view["record_id"]: float(view.get("reliability", 0.8)) for view in views
    }

    values: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for row in field_diff:
        name = row["field"]
        present = [v for v in row["values"] if v["present"]]
        if not present:
            continue
        # Most reliable source wins; ties break deterministically by id.
        ranked = sorted(
            present,
            key=lambda v: (
                -reliability_by_record.get(v["record_id"], 0.8),
                v["record_id"],
            ),
        )
        chosen = ranked[0]
        values[name] = chosen["value"]
        sources[name] = chosen["record_id"]

    return values, sources
