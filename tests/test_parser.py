import pytest

from app.tql import ast_nodes as ast
from app.tql import parse
from app.tql.errors import TQLSyntaxError


def test_empty_query_returns_none():
    assert parse("") is None
    assert parse("   \n\t ") is None


def test_field_predicate_types():
    node = parse('host = "web-01"')
    assert isinstance(node, ast.FieldPredicate)
    assert node.field == "host"
    assert node.op == "="
    assert node.value == "web-01"


def test_bare_value_and_number():
    node = parse("level = error")
    assert node.value == "error"
    node = parse("id = 42")
    assert node.value == 42


def test_boolean_precedence():
    # a AND b OR c  =>  (a AND b) OR c
    node = parse('host = "a" AND level = "e" OR #t')
    assert isinstance(node, ast.LogicalExpr)
    assert node.op == "or"
    assert isinstance(node.left, ast.LogicalExpr)
    assert node.left.op == "and"
    assert isinstance(node.right, ast.TagPredicate)


def test_parentheses_override_precedence():
    node = parse('host = "a" AND (level = "e" OR #t)')
    assert isinstance(node, ast.LogicalExpr)
    assert node.op == "and"
    assert isinstance(node.right, ast.LogicalExpr)
    assert node.right.op == "or"


def test_not_expression():
    node = parse("NOT #verified")
    assert isinstance(node, ast.NotExpr)
    assert isinstance(node.expr, ast.TagPredicate)


def test_temporal_with_window():
    node = parse('level = "error" AFTER #deploy WITHIN 5m')
    assert isinstance(node, ast.TemporalExpr)
    assert node.direction == "after"
    assert node.within_seconds == 300
    assert isinstance(node.left, ast.FieldPredicate)
    assert isinstance(node.right, ast.TagPredicate)


def test_temporal_before_without_window():
    node = parse("#x BEFORE #y")
    assert isinstance(node, ast.TemporalExpr)
    assert node.direction == "before"
    assert node.within_seconds is None


def test_last_window_durations():
    for text, seconds in [("500ms", 0.5), ("30s", 30), ("5m", 300),
                          ("2h", 7200), ("7d", 7 * 86400)]:
        node = parse(f"LAST {text}")
        assert isinstance(node, ast.LastWindow)
        assert node.seconds == seconds


def test_tag_functions():
    node = parse('all_tags("a", "b")')
    assert isinstance(node, ast.TagListPredicate)
    assert node.mode == "all"
    assert node.tags == ("a", "b")
    node = parse('any_tags("x")')
    assert node.mode == "any"
    assert node.tags == ("x",)


def test_missing_value_points_after_eq():
    q = "host ="
    with pytest.raises(TQLSyntaxError) as ei:
        parse(q)
    err = ei.value
    assert err.column == q.index("=") + 2  # EOF 列
    assert err.line == 1
    assert "缺少值" in err.message


def test_missing_operator_points_at_value():
    q = 'host "web-01"'
    with pytest.raises(TQLSyntaxError) as ei:
        parse(q)
    assert ei.value.column == q.index('"web-01"') + 1


def test_unknown_keyword_connector_error():
    q = 'host = "a" andd level = "b"'
    with pytest.raises(TQLSyntaxError) as ei:
        parse(q)
    assert ei.value.column == q.index("andd") + 1
    assert ei.value.fragment == "andd"


def test_bad_duration_unit_points_at_unit():
    q = "#a BEFORE #b WITHIN 3w"
    with pytest.raises(TQLSyntaxError) as ei:
        parse(q)
    assert ei.value.column == q.index("w") + 1
    assert ei.value.fragment == "w"


def test_within_without_temporal_error():
    q = 'host = "a" WITHIN 5m'
    with pytest.raises(TQLSyntaxError) as ei:
        parse(q)
    assert ei.value.column == q.index("WITHIN") + 1


def test_unclosed_paren_points_to_eof():
    q = '(host = "a"'
    with pytest.raises(TQLSyntaxError) as ei:
        parse(q)
    assert ei.value.column == len(q) + 1
    assert ")" in ei.value.message


def test_extra_right_paren():
    q = 'host = "a")'
    with pytest.raises(TQLSyntaxError) as ei:
        parse(q)
    assert ei.value.column == q.index(")") + 1


def test_keyword_as_bare_value_suggests_quotes():
    q = "level = AND"
    with pytest.raises(TQLSyntaxError) as ei:
        parse(q)
    assert ei.value.column == q.index("AND") + 1
    assert "引号" in (ei.value.hint or "")


def test_multiline_error_line_and_column():
    q = 'host = "a"\nAND\nlevel ='
    with pytest.raises(TQLSyntaxError) as ei:
        parse(q)
    err = ei.value
    assert err.line == 3
    assert err.column == len("level =") + 1
    rendered = err.render()
    assert "第 3 行" in rendered
    assert "^" in rendered


def test_rendered_error_contains_source_and_caret():
    q = "foo @"
    with pytest.raises(TQLSyntaxError) as ei:
        parse(q)
    rendered = ei.value.render()
    assert q in rendered
    assert "^" in rendered
    assert ei.value.to_dict()["rendered"] == rendered
