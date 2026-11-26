"""把 TQL AST 编译成参数化 SQLite WHERE 片段。

所有用户值都通过 ``?`` 参数绑定，不做字符串拼接。
前后关系编译为相关 EXISTS 子查询，标签同理。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re

from . import ast_nodes as ast
from .errors import Span, TQLSemanticError


@dataclass(frozen=True)
class FieldSpec:
    column: str
    kind: str  # string | integer | time
    aliases: tuple[str, ...] = ()


FIELDS: dict[str, FieldSpec] = {
    "id": FieldSpec("id", "integer"),
    "ts": FieldSpec("epoch", "time", ("time", "timestamp", "at")),
    "host": FieldSpec("host", "string"),
    "service": FieldSpec("service", "string", ("svc",)),
    "level": FieldSpec("level", "string", ("severity",)),
    "message": FieldSpec("message", "string", ("msg",)),
}

_FIELD_BY_NAME: dict[str, FieldSpec] = {}
for _name, _spec in FIELDS.items():
    _FIELD_BY_NAME[_name] = _spec
    for _alias in _spec.aliases:
        _FIELD_BY_NAME[_alias] = _spec

_STRING_OPS = {"=", "!=", "~", "!~"}
_ORDER_OPS = {"<", "<=", ">", ">="}


def parse_time_value(value: object, span: Span | None, source: str | None) -> float:
    """把 ISO8601 字符串或数字（epoch 秒）转成 epoch 浮点。"""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    text = str(value).strip()
    if re.fullmatch(r"-?\d+(\.\d+)?", text):
        return float(text)
    try:
        normalized = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        raise TQLSemanticError(
            f"无法解析时间值 {text!r}",
            source=source,
            span=span,
            hint="支持 ISO8601，例如 2026-11-25T14:00:00Z 或 2026-11-25 22:00:00",
        ) from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


class Compiler:
    def __init__(self, *, now: float, source: str | None = None) -> None:
        self.now = now
        self.source = source
        self._alias_n = 0

    def new_alias(self, prefix: str = "s") -> str:
        self._alias_n += 1
        return f"_{prefix}{self._alias_n}"

    def error(self, node_span: Span | None, message: str, hint: str | None = None):
        return TQLSemanticError(message, source=self.source, span=node_span, hint=hint)

    # -- 入口 -----------------------------------------------------------
    def compile(self, node: ast.Node | None, alias: str = "e") -> tuple[str, list]:
        if node is None:
            return "1=1", []
        return self._compile(node, alias)

    def _compile(self, node: ast.Node, a: str) -> tuple[str, list]:
        if isinstance(node, ast.FieldPredicate):
            return self._field(node, a)
        if isinstance(node, ast.TagPredicate):
            return self._tag(node.tag, a, node.span)
        if isinstance(node, ast.TagListPredicate):
            return self._tag_list(node, a)
        if isinstance(node, ast.LastWindow):
            return f"{a}.epoch >= ?", [self.now - node.seconds]
        if isinstance(node, ast.NotExpr):
            sql, params = self._compile_required(node.expr, a)
            return f"NOT ({sql})", params
        if isinstance(node, ast.LogicalExpr):
            ls, lp = self._compile_required(node.left, a)
            rs, rp = self._compile_required(node.right, a)
            op = "AND" if node.op == "and" else "OR"
            return f"({ls}) {op} ({rs})", [*lp, *rp]
        if isinstance(node, ast.TemporalExpr):
            return self._temporal(node, a)
        raise self.error(getattr(node, "span", None), f"未知 AST 节点: {type(node).__name__}")

    def _compile_required(self, node: ast.Node | None, a: str) -> tuple[str, list]:
        if node is None:
            return "1=1", []
        return self._compile(node, a)

    # -- 字段 -----------------------------------------------------------
    def _field(self, node: ast.FieldPredicate, a: str) -> tuple[str, list]:
        if node.field == "tag":
            if node.op == "=":
                return self._tag_exists_sql(str(node.value), a)
            if node.op == "!=":
                sql, params = self._tag_exists_sql(str(node.value), a)
                return f"NOT {sql}", params
            raise self.error(
                node.op_span,
                f"字段 tag 仅支持 = 或 !=，当前为 {node.op!r}",
                "也可以使用 #标签 或 all_tags(...) / any_tags(...)",
            )
        spec = _FIELD_BY_NAME.get(node.field)
        if spec is None:
            raise self.error(
                node.field_span or node.span,
                f"未知事件字段 {node.field!r}",
                "可用字段: id, ts, host, service, level, message",
            )
        col = f"{a}.{spec.column}"
        op = node.op

        if spec.kind == "time":
            if op == "~" or op == "!~":
                raise self.error(node.op_span, "时间字段 ts 不支持包含匹配 ~",
                                 "请使用 =、!=、>、>=、<、<= 或 LAST 15m")
            epoch = parse_time_value(node.value, node.value_span, self.source)
            sql_op = {"=": "=", "!=": "!=", "<": "<",
                      "<=": "<=", ">": ">", ">=": ">="}[op]
            return f"{col} {sql_op} ?", [epoch]

        if spec.kind == "integer":
            if op not in ("=", "!=", "<", "<=", ">", ">="):
                raise self.error(node.op_span, f"整数字段 id 不支持运算符 {op!r}")
            try:
                ivalue = int(str(node.value))
            except (TypeError, ValueError):
                raise self.error(
                    node.value_span, f"字段 id 需要整数，但得到 {node.value!r}"
                ) from None
            sql_op = {"=": "=", "!=": "!=", "<": "<", "<=": "<=",
                      ">": ">", ">=": ">="}[op]
            return f"{col} {sql_op} ?", [ivalue]

        # string
        if op in _ORDER_OPS:
            raise self.error(
                node.op_span,
                f"字符串字段 {node.field!r} 不支持顺序比较 {op}",
                "顺序比较仅支持 ts / id；文本匹配请用 =、!=、~（包含）、!~（不包含）",
            )
        value = "" if node.value is None else str(node.value)
        if op == "=":
            return f"{col} = ?", [value]
        if op == "!=":
            return f"{col} != ?", [value]
        if op == "~":
            return f"INSTR(LOWER({col}), LOWER(?)) > 0", [value]
        # !~
        return f"INSTR(LOWER({col}), LOWER(?)) = 0", [value]

    # -- 标签 -----------------------------------------------------------
    def _tag_exists_sql(self, tag: str, event_alias: str) -> tuple[str, list]:
        ta = self.new_alias("tag")
        return (
            f"EXISTS (SELECT 1 FROM event_tags {ta} "
            f"WHERE {ta}.event_id = {event_alias}.id AND {ta}.tag = ?)",
            [tag.lower()],
        )

    def _tag(self, tag: str, a: str, span: Span | None) -> tuple[str, list]:
        if not tag:
            raise self.error(span, "标签名不能为空")
        return self._tag_exists_sql(tag, a)

    def _tag_list(self, node: ast.TagListPredicate, a: str) -> tuple[str, list]:
        if not node.tags:
            raise self.error(node.span, "标签函数至少需要一个标签")
        parts: list[str] = []
        params: list = []
        for tag in node.tags:
            sql, ps = self._tag_exists_sql(tag, a)
            parts.append(sql)
            params.extend(ps)
        joiner = " AND " if node.mode == "all" else " OR "
        return "(" + joiner.join(parts) + ")", params

    # -- 前后关系 -------------------------------------------------------
    def _temporal(self, node: ast.TemporalExpr, a: str) -> tuple[str, list]:
        if node.left is None or node.right is None:
            raise self.error(node.span, "BEFORE/AFTER 两侧都必须有事件条件")
        left_sql, left_params = self._compile(node.left, a)

        anchor = self.new_alias("anc")
        right_sql, right_params = self._compile(node.right, anchor)

        if node.direction == "after":
            # 主体事件 a 在参照事件 anchor 之后：anchor.epoch < a.epoch
            relation = f"{anchor}.epoch < {a}.epoch"
            gap = f"({a}.epoch - {anchor}.epoch)"
        else:
            # 主体事件在参照事件之前：anchor.epoch > a.epoch
            relation = f"{anchor}.epoch > {a}.epoch"
            gap = f"({anchor}.epoch - {a}.epoch)"

        sql = (
            f"({left_sql}) AND EXISTS ("
            f"SELECT 1 FROM events {anchor} "
            f"WHERE ({right_sql}) AND {relation}"
        )
        params = [*left_params, *right_params]
        if node.within_seconds is not None:
            sql += f" AND {gap} <= ?"
            params.append(node.within_seconds)
        sql += ")"
        return sql, params


def compile_query(
    node: ast.Node | None, *, now: float, source: str | None = None
) -> tuple[str, list]:
    return Compiler(now=now, source=source).compile(node)
