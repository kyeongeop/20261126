"""针对固定数据集验证 TQL 语义、限制与分页。"""

import pytest

from app.tql import TQLSemanticError
from tests.conftest import NOW


def ids(result):
    return [item["id"] for item in result["items"]]


def search(repo, q, **kw):
    kw.setdefault("now", NOW)
    return repo.search_tql(q, **kw)


# -- 字段过滤 -----------------------------------------------------------
def test_empty_query_returns_all(repo):
    result = search(repo, "")
    assert result["total"] == 12
    assert result["returned"] == 12


def test_field_equality(repo):
    assert ids(search(repo, 'level = "error"')) == [1, 5, 6, 7, 8]


def test_bare_value_equality(repo):
    assert ids(search(repo, "level = error")) == [1, 5, 6, 7, 8]


def test_field_not_equal(repo):
    result = search(repo, 'level != "info"')
    assert result["total"] == 7  # 5 error + 2 warn


def test_contains_case_insensitive(repo):
    result = search(repo, 'message ~ "TIMEOUT"')
    # 只有 5/6 的 message 含连续的 timeout；7/8 仅带 #timeout 标签或写作 timed out
    assert ids(result) == [5, 6]


def test_not_contains(repo):
    result = search(repo, 'message !~ "timeout" AND level = "error"')
    assert ids(result) == [1, 7, 8]


def test_field_alias_service_svc(repo):
    assert search(repo, 'svc = "checkout"')["total"] == 6


def test_id_integer_predicate(repo):
    assert ids(search(repo, "id > 10")) == [11, 12]


def test_time_range_with_iso(repo):
    from app.seed import iso_utc
    from tests.conftest import BASE_EPOCH

    start = iso_utc(BASE_EPOCH + 10 * 60)
    result = search(repo, f'ts >= "{start}"')
    assert ids(result) == [5, 6, 7, 8, 9, 10, 11, 12]


# -- 布尔组合 -----------------------------------------------------------
def test_and_or_parentheses(repo):
    q = 'host = "api-01" AND (level = "error" OR level = "warn")'
    assert ids(search(repo, q)) == [5, 9]


def test_not_operator(repo):
    assert search(repo, "#deploy AND NOT #rollback")["total"] == 2


# -- 证据标签组合 -------------------------------------------------------
def test_hash_tag(repo):
    assert ids(search(repo, "#deploy")) == [2, 3, 10]


def test_tag_equality_form(repo):
    assert ids(search(repo, 'tag = "deploy"')) == [2, 3, 10]


def test_all_tags(repo):
    assert ids(search(repo, 'all_tags("db-lock", "timeout")')) == [7]


def test_any_tags(repo):
    assert set(ids(search(repo, 'any_tags("disk", "customer-report")'))) == {1, 8}


def test_tag_boolean_combination(repo):
    q = "(#timeout OR #db-lock) AND #metrics"
    assert ids(search(repo, q)) == [4]


# -- 前后关系 + 时间窗口 ------------------------------------------------
def test_after_deploy_within_20m_boundary(repo):
    q = 'level = "error" AFTER #deploy WITHIN 20m'
    assert ids(search(repo, q)) == [5, 6, 7, 8]


def test_after_deploy_within_15m_excludes_boundary_case(repo):
    q = 'level = "error" AFTER #deploy WITHIN 15m'
    assert ids(search(repo, q)) == [5, 6, 7]


def test_after_without_window(repo):
    q = 'level = "error" AFTER #deploy'
    assert ids(search(repo, q)) == [5, 6, 7, 8]


def test_before_rollback_within_40m(repo):
    q = 'level = "error" BEFORE #rollback WITHIN 40m'
    assert ids(search(repo, q)) == [8]


def test_before_rollback_within_45m_boundary(repo):
    q = 'level = "error" BEFORE #rollback WITHIN 45m'
    assert ids(search(repo, q)) == [7, 8]


def test_before_rollback_within_50m(repo):
    q = 'level = "error" BEFORE #rollback WITHIN 50m'
    assert ids(search(repo, q)) == [5, 6, 7, 8]


def test_temporal_with_complex_anchor(repo):
    q = 'level = "error" AFTER (#config-change OR #rollback) WITHIN 15m'
    # config-change @2 -> 5@12 gap10, 6@13 gap11, 7@15 gap13 ; 8@22 gap20 排除
    assert ids(search(repo, q)) == [5, 6, 7]


def test_combined_temporal_and_field(repo):
    q = '#timeout AND service = "checkout" AFTER #deploy WITHIN 30m'
    assert ids(search(repo, q)) == [5, 6]


# -- LAST 窗口 ----------------------------------------------------------
def test_last_window(repo):
    assert ids(search(repo, "LAST 30m")) == [9, 10, 11, 12]


def test_last_window_combined(repo):
    assert ids(search(repo, "LAST 30m AND #rollback")) == [10]


# -- 语义错误 -----------------------------------------------------------
def test_unknown_field_is_semantic_error_with_span(repo):
    with pytest.raises(TQLSemanticError) as ei:
        search(repo, 'nope = "x"')
    assert ei.value.column == 1
    assert ei.value.fragment == "nope"


def test_ordering_on_string_field_rejected(repo):
    with pytest.raises(TQLSemanticError) as ei:
        search(repo, 'host > "a"')
    assert ei.value.column == 6  # > 的列


def test_bad_time_value_rejected_with_span(repo):
    q = 'ts = "not-a-date"'
    with pytest.raises(TQLSemanticError) as ei:
        search(repo, q)
    assert ei.value.column == q.index('"not-a-date"') + 1


# -- 限制 / 分页 --------------------------------------------------------
def test_limit_caps_rows_and_flags_truncated(repo):
    result = search(repo, "", limit=3)
    assert ids(result) == [1, 2, 3]
    assert result["returned"] == 3
    assert result["total"] == 12
    assert result["truncated"] is True


def test_offset_pagination(repo):
    result = search(repo, "", limit=5, offset=10)
    assert ids(result) == [11, 12]
    assert result["truncated"] is False


def test_desc_order(repo):
    result = search(repo, "", limit=3, order="desc")
    assert ids(result) == [12, 11, 10]


def test_limit_clamped_to_max(repo):
    result = repo.search_tql("", now=NOW, limit=10_000)
    assert result["limit"] == 500
    assert result["clamped"] is True


def test_evidence_hydrated(repo):
    result = search(repo, "id = 5")
    item = result["items"][0]
    assert item["evidence"]
    assert item["evidence"][0]["kind"] == "log"
