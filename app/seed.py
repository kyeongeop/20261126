"""Idempotent demo data: one user login reported by two systems with skew."""

from __future__ import annotations

import sqlite3
from typing import Any

from . import config, service
from .database import get_connection

SEED_INCIDENT_ID = config.DEFAULT_INCIDENT_ID
MARKER_RECORD = "rec-alice-idp"


def seed_demo(
    database_path: str | None = None, *, conn: sqlite3.Connection | None = None
) -> dict[str, Any]:
    own_connection = conn is None
    if conn is None:
        conn = get_connection(database_path or config.DATABASE_PATH)

    try:
        existing = conn.execute(
            "SELECT 1 FROM source_records WHERE id = ?", (MARKER_RECORD,)
        ).fetchone()
        if existing is not None:
            return {"seeded": False, "reason": "already-seeded"}

        service.create_incident(
            conn,
            incident_id=SEED_INCIDENT_ID,
            title="2026-11-20 异常登录时间冲突排查",
            severity="high",
        )
        service.create_source(
            conn,
            code="corp_idp",
            name="企业统一身份认证 (IdP)",
            reliability=0.95,
        )
        service.create_source(
            conn,
            code="vpn_gw",
            name="VPN 接入网关",
            reliability=0.82,
        )

        # -- Alice: same login, ~5 minute clock skew, strong corroboration --
        alice_idp, _ = service.ingest_record(
            conn,
            record_id="rec-alice-idp",
            source_code="corp_idp",
            external_id="IDP-EVT-1001",
            event_type="user_login",
            user_id="alice.chen",
            occurred_at="2026-11-20T09:00:12Z",
            payload={
                "result": "success",
                "ip_address": "203.0.113.8",
                "device_id": "dev-alice-mbp",
                "device_name": "Alice MacBook Pro",
                "session_id": "idp-sess-7f31a0",
                "user_agent": "Mozilla/5.0 Chrome/130 macOS",
                "location": "中国-上海",
                "asn": "AS4812 中国电信",
                "auth_method": "password+TOTP",
                "mfa_method": "TOTP",
                "auth_provider": "corp-idp",
                "app": "VPN",
            },
        )
        alice_vpn, _ = service.ingest_record(
            conn,
            record_id="rec-alice-vpn",
            source_code="vpn_gw",
            external_id="VPN-LOG-55901",
            event_type="user_login",
            user_id="alice.chen",
            occurred_at="2026-11-20T17:04:57+08:00",
            payload={
                "result": "success",
                "ip_address": "203.0.113.8",
                "device_id": "dev-alice-mbp",
                "session_id": "vpn-sess-aa92e4",
                "user_agent": "Mozilla/5.0 Chrome/130 macOS",
                "location": "上海",
                "asn": "AS4812 中国电信",
                "auth_method": "client-certificate",
                "protocol": "IKEv2",
                "bytes_in": 184320,
                "bytes_out": 40211,
            },
        )
        service.create_candidate(
            conn,
            [alice_idp["id"], alice_vpn["id"]],
            incident_id=SEED_INCIDENT_ID,
            candidate_id="cand-alice",
        )

        # -- Bob: hours apart, different IP/device/geo -> likely split -------
        bob_idp, _ = service.ingest_record(
            conn,
            record_id="rec-bob-idp",
            source_code="corp_idp",
            external_id="IDP-EVT-1042",
            event_type="user_login",
            user_id="bob.wang",
            occurred_at="2026-11-21T01:10:05Z",
            payload={
                "result": "success",
                "ip_address": "198.51.100.24",
                "device_id": "dev-bob-phone12",
                "device_name": "Bob Pixel",
                "location": "中国-北京",
                "auth_method": "password+TOTP",
            },
        )
        bob_vpn, _ = service.ingest_record(
            conn,
            record_id="rec-bob-vpn",
            source_code="vpn_gw",
            external_id="VPN-LOG-56320",
            event_type="user_login",
            user_id="bob.wang",
            occurred_at="2026-11-21T15:52:40+08:00",
            payload={
                "result": "success",
                "ip_address": "192.0.2.77",
                "device_id": "dev-android-unknown",
                "location": "新加坡",
                "auth_method": "client-certificate",
                "protocol": "WireGuard",
            },
        )
        service.create_candidate(
            conn,
            [bob_idp["id"], bob_vpn["id"]],
            incident_id=SEED_INCIDENT_ID,
            candidate_id="cand-bob",
        )

        return _seed_remaining(conn)
    finally:
        if own_connection:
            conn.close()


def _seed_remaining(conn: sqlite3.Connection) -> dict[str, Any]:
    # -- Carol: ~39 minutes apart, sparse overlap -> genuinely ambiguous -----
    carol_idp, _ = service.ingest_record(
        conn,
        record_id="rec-carol-idp",
        source_code="corp_idp",
        external_id="IDP-EVT-1088",
        event_type="user_login",
        user_id="carol.li",
        occurred_at="2026-11-22T14:20:00Z",
        payload={
            "result": "success",
            "ip_address": "203.0.113.55",
            "device_id": "dev-carol-mac",
            "user_agent": "Safari/18.1 macOS",
            "auth_method": "password+TOTP",
        },
    )
    carol_vpn, _ = service.ingest_record(
        conn,
        record_id="rec-carol-vpn",
        source_code="vpn_gw",
        external_id="VPN-LOG-57002",
        event_type="user_login",
        user_id="carol.li",
        occurred_at="2026-11-22T22:58:41+08:00",
        payload={
            "result": "success",
            "ip_address": "203.0.113.55",
            "device_id": "dev-carol-ipad",
            "user_agent": "Safari/18.1 iPadOS",
            "auth_method": "client-certificate",
        },
    )
    service.create_candidate(
        conn,
        [carol_idp["id"], carol_vpn["id"]],
        incident_id=SEED_INCIDENT_ID,
        candidate_id="cand-carol",
    )

    # -- Dave: already reviewed & merged, shown on the timeline immediately --
    dave_idp, _ = service.ingest_record(
        conn,
        record_id="rec-dave-idp",
        source_code="corp_idp",
        external_id="IDP-EVT-0900",
        event_type="user_login",
        user_id="dave.zhao",
        occurred_at="2026-11-19T08:00:00Z",
        payload={
            "result": "success",
            "ip_address": "198.18.0.10",
            "device_id": "dev-dave-laptop",
            "location": "中国-深圳",
            "auth_method": "password+passkey",
        },
    )
    dave_vpn, _ = service.ingest_record(
        conn,
        record_id="rec-dave-vpn",
        source_code="vpn_gw",
        external_id="VPN-LOG-54010",
        event_type="user_login",
        user_id="dave.zhao",
        occurred_at="2026-11-19T08:01:20Z",
        payload={
            "result": "success",
            "ip_address": "198.18.0.10",
            "device_id": "dev-dave-laptop",
            "location": "深圳",
            "auth_method": "client-certificate",
            "protocol": "IKEv2",
        },
    )
    service.create_candidate(
        conn,
        [dave_idp["id"], dave_vpn["id"]],
        incident_id=SEED_INCIDENT_ID,
        candidate_id="cand-dave",
    )
    service.keep_candidate(
        conn,
        "cand-dave",
        analyst="seed-bot",
        note="演示数据：时钟轻微偏差，字段可交叉印证，确认合并。",
    )
    return {"seeded": True, "incident_id": SEED_INCIDENT_ID}


def main() -> None:
    result = seed_demo()
    print(result)


def reset_demo(*, conn: sqlite3.Connection) -> dict[str, Any]:
    """Clear every table and rebuild the deterministic demo dataset."""

    for table in (
        "review_actions",
        "timeline_event_records",
        "timeline_events",
        "candidate_records",
        "merge_candidates",
        "source_records",
        "sources",
        "incidents",
    ):
        conn.execute(f"DELETE FROM {table}")
    conn.execute("DELETE FROM sqlite_sequence WHERE name = 'review_actions'")
    conn.commit()
    return seed_demo(conn=conn)


if __name__ == "__main__":
    main()
