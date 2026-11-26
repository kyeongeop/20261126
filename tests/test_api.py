"""FastAPI 层测试：查询、错误体定位、限制、经典筛选、导出。"""

from tests.conftest import NOW


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_meta_lists_limits_and_examples(client):
    data = client.get("/api/meta").json()
    assert data["limits"]["max_limit"] == 500
    assert data["examples"]
    assert "BEFORE" in data["operators"]["temporal"][0]


def test_get_query_endpoint(client):
    resp = client.get(
        "/api/timeline/query",
        params={"q": 'level = "error"', "now": NOW},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5
    assert [i["id"] for i in data["items"]] == [1, 5, 6, 7, 8]


def test_post_query_endpoint(client):
    resp = client.post(
        "/api/timeline/query",
        json={"query": "#deploy AND NOT #rollback", "now": NOW},
    )
    assert resp.status_code == 200
    assert resp.json()["total"] == 2


def test_short_alias(client):
    resp = client.get("/api/query", params={"q": "#rollback", "now": NOW})
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


def test_syntax_error_response_has_location(client):
    q = 'level = "error" AFTER #deploy WITHIN 5x'
    resp = client.get("/api/timeline/query", params={"q": q})
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["kind"] == "syntax"
    assert err["line"] == 1
    assert err["column"] == q.index("x") + 1
    assert err["fragment"] == "x"
    assert "^" in err["rendered"]


def test_semantic_error_response_has_location(client):
    q = "unknown_field = 1"
    resp = client.post("/api/timeline/query", json={"query": q})
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["kind"] == "semantic"
    assert err["column"] == 1
    assert err["fragment"] == "unknown_field"


def test_limit_cap_and_clamp_flag(client):
    resp = client.get("/api/timeline/query", params={"limit": 2, "now": NOW})
    data = resp.json()
    assert data["returned"] == 2
    assert data["truncated"] is True

    resp = client.get("/api/timeline/query", params={"limit": 99999})
    data = resp.json()
    assert data["limit"] == 500
    assert data["clamped"] is True


def test_invalid_limit_returns_400(client):
    resp = client.get("/api/timeline/query", params={"limit": 0})
    assert resp.status_code == 400


def test_classic_host_and_start_filter(client):
    from app.seed import iso_utc
    from tests.conftest import BASE_EPOCH

    start = iso_utc(BASE_EPOCH + 11 * 60)
    resp = client.get("/api/events", params={"host": "api-01", "start": start})
    data = resp.json()
    # api-01 且时间 >= 11m：id 12? 不，5@12,9@40,11@66,12@70；id3@2 被开始时间过滤
    assert [i["id"] for i in data["items"]] == [5, 9, 11, 12]


def test_hosts_metadata(client):
    hosts = {h["host"] for h in client.get("/api/hosts").json()["hosts"]}
    assert {"api-01", "db-01", "web-01"} <= hosts


def test_tags_metadata(client):
    tags = {t["tag"] for t in client.get("/api/tags").json()["tags"]}
    assert {"deploy", "timeout", "db-lock", "rollback"} <= tags


def test_export_csv(client):
    resp = client.get(
        "/api/timeline/export",
        params={"q": 'level = "error"', "format": "csv", "now": NOW},
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "attachment" in resp.headers["content-disposition"]
    body = resp.content.decode("utf-8-sig")
    lines = body.strip().split("\n")
    assert "时间(UTC)" in lines[0]
    assert len(lines) == 6  # 表头 + 5 条 error
    assert "timeout" in body
    assert resp.headers["x-tql-exported"] == "5"


def test_export_json(client):
    resp = client.get(
        "/api/timeline/export",
        params={"q": "#deploy", "format": "json", "now": NOW},
    )
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    data = resp.json()
    assert len(data) == 3
    assert {item["id"] for item in data} == {2, 3, 10}


def test_export_bad_format_400(client):
    resp = client.get("/api/timeline/export", params={"format": "xml"})
    assert resp.status_code == 400


def test_export_short_alias(client):
    resp = client.get("/api/export", params={"format": "json", "now": NOW})
    assert resp.status_code == 200
    assert len(resp.json()) == 12


def test_index_page_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "TQL" in resp.text
