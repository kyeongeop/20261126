from app.tql.lexer import TokenType, tokenize
from app.tql.errors import TQLSyntaxError


def types(source):
    return [t.type for t in tokenize(source) if t.type != TokenType.EOF]


def test_basic_field_predicate_tokens():
    tokens = tokenize('host = "web-01"')
    assert [t.type for t in tokens[:-1]] == [
        TokenType.IDENT, TokenType.EQ, TokenType.STRING
    ]
    assert tokens[0].offset == 0
    assert tokens[2].value == "web-01"


def test_keywords_case_insensitive():
    tokens = tokenize("level = \"x\" aNd #t BeFoRe #u WiThIn 5m LaSt 1h")
    mapping = {t.text.lower(): t.type for t in tokens}
    assert mapping["and"] == TokenType.AND
    assert mapping["before"] == TokenType.BEFORE
    assert mapping["within"] == TokenType.WITHIN
    assert mapping["last"] == TokenType.LAST


def test_tag_token_position():
    tokens = tokenize("  #db-lock")
    tag = tokens[0]
    assert tag.type == TokenType.TAG
    assert tag.value == "db-lock"
    assert tag.line == 1
    assert tag.column == 3
    assert tag.length == len("#db-lock")


def test_multiline_positions():
    source = "host = \"a\"\nAND level = \"error\""
    tokens = tokenize(source)
    and_tok = next(t for t in tokens if t.type == TokenType.AND)
    assert and_tok.line == 2
    assert and_tok.column == 1


def test_number_and_duration_tokens():
    tokens = tokenize("WITHIN 500ms")
    assert tokens[1].type == TokenType.NUMBER
    assert tokens[1].value == 500
    assert tokens[2].type == TokenType.IDENT
    assert tokens[2].text == "ms"


def test_operators():
    assert TokenType.NE in types("a != b")
    assert TokenType.LE in types("ts <= \"x\"")
    assert TokenType.GE in types("ts >= \"x\"")
    assert TokenType.NOT_CONTAINS in types("m !~ \"x\"")
    assert TokenType.CONTAINS in types("m ~= \"x\"")


def test_unterminated_string_has_position_and_fragment():
    try:
        tokenize('level = "error')
    except TQLSyntaxError as exc:
        assert exc.line == 1
        assert exc.column == 9  # 开引号位置
        assert exc.fragment.startswith('"error')
        assert "结束引号" in exc.message
    else:  # pragma: no cover
        raise AssertionError("应当抛出 TQLSyntaxError")


def test_illegal_char_points_at_char():
    source = "host @ \"x\""
    try:
        tokenize(source)
    except TQLSyntaxError as exc:
        assert exc.column == source.index("@") + 1
        assert exc.fragment == "@"
    else:  # pragma: no cover
        raise AssertionError("应当抛出 TQLSyntaxError")


def test_empty_hash_tag_error():
    try:
        tokenize("# AND")
    except TQLSyntaxError as exc:
        assert exc.column == 1
        assert "#" in exc.fragment
    else:  # pragma: no cover
        raise AssertionError("应当抛出 TQLSyntaxError")
