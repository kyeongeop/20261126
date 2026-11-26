"""错误定位/渲染的额外约束：列、片段、CJK 对齐、可序列化。"""

import json

import pytest

from app.tql import TQLSyntaxError, parse
from app.tql.errors import display_width


def test_error_dict_is_json_serializable():
    q = "host @"
    with pytest.raises(TQLSyntaxError) as ei:
        parse(q)
    payload = json.dumps(ei.value.to_dict(), ensure_ascii=False)
    assert "@" in payload


def test_cjk_caret_alignment():
    # 错误 token 位于若干中文字符之后
    q = 'message ~ "支付超时" AND host ='
    with pytest.raises(TQLSyntaxError) as ei:
        parse(q)
    err = ei.value
    assert err.column == len(q) + 1
    rendered = err.render()
    caret_line = rendered.splitlines()[2]
    # 插入符前的空格显示宽度应等于源码行在该列之前的显示宽度 +  gutter 偏移
    prefix = q[: err.column - 1]
    assert display_width(prefix) > len(prefix)  # 确实含宽字符
    assert caret_line.rstrip().endswith("^")
    # caret 行中 '| ' 之后的空格宽度 + 1(caret) 与前缀宽度一致
    after_bar = caret_line.split("|", 1)[1]
    leading_spaces = after_bar[: len(after_bar) - len(after_bar.lstrip(" "))]
    # '|' 后有一个分隔空格，之后才是与源码前缀等宽的 padding
    assert display_width(leading_spaces) == display_width(prefix) + 1


def test_multiline_fragment_points_to_second_line():
    q = "#a BEFORE #b\nWITHIN 3x"
    with pytest.raises(TQLSyntaxError) as ei:
        parse(q)
    err = ei.value
    assert err.line == 2
    # 第二行 "WITHIN 3x" 中 x 位于第 9 列
    assert err.column == 9
    assert err.fragment == "x"
