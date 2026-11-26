"""守卫：/api/meta 暴露的示例必须全部是合法 TQL。"""

from app.tql import parse


def test_all_meta_examples_parse(client):
    examples = client.get("/api/meta").json()["examples"]
    assert examples
    for query in examples:
        try:
            parse(query)
        except Exception as exc:  # pragma: no cover - 明确失败信息
            raise AssertionError(f"示例无法解析: {query!r} -> {exc}") from exc


def test_all_meta_examples_run_on_sample(client):
    examples = client.get("/api/meta").json()["examples"]
    for query in examples:
        resp = client.get("/api/query", params={"q": query})
        assert resp.status_code == 200, (query, resp.text)
