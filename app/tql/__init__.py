"""小型本地时间线查询语言 TQL (Timeline Query Language)。

支持:
  * 事件字段过滤: host = "web-01" AND level != "info"
  * 包含匹配:     message ~ "timeout"
  * 证据标签组合: #deploy AND (#rca OR #trace) / all_tags("a","b")
  * 前后关系:     level = "error" AFTER #deploy
  * 时间窗口:     ... AFTER #deploy WITHIN 10m  以及  LAST 30m

用法::

    from app.tql import parse, compile_query, TQLSyntaxError

    ast = parse('level = "error" AFTER #deploy WITHIN 10m')
    where_sql, params = compile_query(ast, now=time.time(), source=q)
"""

from .errors import (
    Span,
    TQLError,
    TQLSemanticError,
    TQLSyntaxError,
    display_width,
)
from .lexer import Lexer, Token, TokenType, tokenize
from .parser import Parser, parse
from .compiler import FIELDS, Compiler, compile_query, parse_time_value

__all__ = [
    "Span",
    "TQLError",
    "TQLSyntaxError",
    "TQLSemanticError",
    "display_width",
    "Lexer",
    "Token",
    "TokenType",
    "tokenize",
    "Parser",
    "parse",
    "Compiler",
    "compile_query",
    "parse_time_value",
    "FIELDS",
]
