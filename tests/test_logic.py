from __future__ import annotations

from app import logic


def _view(rid, source, reliability, when, **payload):
    return {
        "record_id": rid,
        "source_code": source,
        "source_name": source.upper(),
        "reliability": reliability,
        "event_type": "user_login",
        "user_id": "alice",
        "occurred_at": when,
        "payload": payload,
        "fields": logic.extract_fields(
            event_type="user_login",
            user_id="alice",
            occurred_at=when,
            payload=payload,
        ),
    }


def test_parse_z_suffix_and_offset_normalise_to_utc():
    assert logic.to_utc_iso("2026-11-20T17:04:57+08:00") == "2026-11-20T09:04:57Z"
    assert logic.to_utc_iso("2026-11-20T09:00:12Z") == "2026-11-20T09:00:12Z"


def test_human_delta():
    assert logic.human_delta(45) == "45秒"
    assert logic.human_delta(291) == "4分51秒"
    assert logic.human_delta(3600 * 6 + 42 * 60) == "6小时42分"


def test_time_comparison_lists_each_source_and_delta():
    views = [
        _view("r1", "idp", 0.95, "2026-11-20T09:00:12Z"),
        _view("r2", "vpn", 0.8, "2026-11-20T09:04:57Z"),
    ]
    cmp_ = logic.build_time_comparison(views)
    assert cmp_["delta_seconds"] == 285
    assert cmp_["delta_human"] == "4分45秒"
    codes = [e["source_code"] for e in cmp_["entries"]]
    assert codes == ["idp", "vpn"]  # earliest first
    assert cmp_["entries"][0]["is_earliest"] is True
    assert cmp_["entries"][1]["offset_human"] == "晚 4分45秒"


def test_field_diff_flags_only_true_conflicts():
    views = [
        _view(
            "r1", "idp", 0.95, "2026-11-20T09:00:12Z",
            ip_address="203.0.113.8", session_id="A", location="Shanghai",
        ),
        _view(
            "r2", "vpn", 0.8, "2026-11-20T09:04:57Z",
            ip_address="203.0.113.8", session_id="Z", location="Shanghai ",
        ),
    ]
    diff = {row["field"]: row for row in logic.build_field_diff(views)}
    assert diff["ip_address"]["conflict"] is False
    assert diff["location"]["conflict"] is False  # whitespace normalised
    assert diff["session_id"]["conflict"] is True
    assert diff["occurred_at"]["conflict"] is True
    # Every conflict row still carries one value per source.
    assert len(diff["session_id"]["values"]) == 2


def test_high_confidence_for_close_corroborated_login():
    views = [
        _view("r1", "idp", 0.95, "2026-11-20T09:00:12Z",
              ip_address="203.0.113.8", device_id="d77", result="success"),
        _view("r2", "vpn", 0.8, "2026-11-20T09:02:00Z",
              ip_address="203.0.113.8", device_id="d77", result="success"),
    ]
    result = logic.score_match(views)
    assert result["label"] == "high"
    assert result["score"] >= 0.8
    assert 0 <= result["trust_adjusted_score"] <= result["score"]
    assert {c["key"] for c in result["components"]} == {
        "identity", "time", "attributes"
    }


def test_low_confidence_for_distant_divergent_login():
    views = [
        _view("r1", "idp", 0.95, "2026-11-21T01:10:05Z",
              ip_address="198.51.100.24", device_id="d1", location="Beijing"),
        _view("r2", "vpn", 0.8, "2026-11-21T07:52:40Z",
              ip_address="192.0.2.77", device_id="d2", location="Singapore"),
    ]
    result = logic.score_match(views)
    assert result["label"] == "low"
    assert result["score"] < 0.55


def test_different_user_cannot_score_full_identity():
    a = _view("r1", "idp", 0.9, "2026-11-20T09:00:00Z")
    b = _view("r2", "vpn", 0.9, "2026-11-20T09:00:30Z")
    b["user_id"] = "bob"
    b["fields"]["user_id"] = "bob"
    result = logic.score_match([a, b])
    identity = next(c for c in result["components"] if c["key"] == "identity")
    assert identity["score"] < identity["max"]


def test_canonical_value_prefers_more_reliable_source():
    views = [
        _view("r1", "idp", 0.95, "2026-11-20T09:00:12Z", mfa_method="totp"),
        _view("r2", "vpn", 0.4, "2026-11-20T09:05:00Z", mfa_method="cert"),
    ]
    diff = logic.build_field_diff(views)
    values, sources = logic.choose_canonical_values(diff, views)
    assert values["mfa_method"] == "totp"
    assert sources["mfa_method"] == "r1"
    assert sources["occurred_at"] == "r1"
