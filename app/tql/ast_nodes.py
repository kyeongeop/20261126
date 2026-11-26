"""TQL 抽象语法树节点。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .errors import Span


@dataclass
class Node:
    span: Span | None = None


@dataclass
class FieldPredicate(Node):
    """字段比较：host = "web-01"、level != "info"、message ~ "timeout"。"""

    field: str = ""
    op: str = "="
    value: object = None
    field_span: Span | None = None
    op_span: Span | None = None
    value_span: Span | None = None


@dataclass
class TagPredicate(Node):
    """单个证据标签：#deploy 或 tag = "deploy"。"""

    tag: str = ""


@dataclass
class TagListPredicate(Node):
    """标签组合函数：all_tags("a","b") / any_tags("a","b")。"""

    mode: Literal["all", "any"] = "all"
    tags: tuple[str, ...] = ()


@dataclass
class LastWindow(Node):
    """相对时间窗口：LAST 15m。"""

    seconds: float = 0.0
    duration_span: Span | None = None


@dataclass
class NotExpr(Node):
    expr: Node | None = None


@dataclass
class LogicalExpr(Node):
    """二元逻辑表达式：AND / OR。"""

    op: Literal["and", "or"] = "and"
    left: Node | None = None
    right: Node | None = None
    op_span: Span | None = None


@dataclass
class TemporalExpr(Node):
    """前后关系 + 可选时间窗口：A AFTER B WITHIN 5m。

    direction="after" 表示 left 事件发生在 right 事件之后；
    direction="before" 表示 left 事件发生在 right 事件之前。
    within_seconds 给出两者最大间隔（窗口），None 表示不限间隔。
    """

    left: Node | None = None
    direction: Literal["before", "after"] = "after"
    right: Node | None = None
    within_seconds: float | None = None
    direction_span: Span | None = None
    within_span: Span | None = None
