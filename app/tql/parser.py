"""TQL 递归下降解析器。

文法（简化）::

    query    := or_expr EOF
    or_expr  := and_expr (OR and_expr)*
    and_expr := unary (AND unary)*
    unary    := NOT unary | temporal
    temporal := primary ((BEFORE|AFTER) primary)? (WITHIN duration)?
    primary  := "(" or_expr ")" | LAST duration | tags_call
              | TAG | IDENT op value
    duration := NUMBER unit
"""

from __future__ import annotations

from . import ast_nodes as ast
from .errors import Span, TQLSyntaxError
from .lexer import Token, TokenType, tokenize


_UNIT_SECONDS = {
    "ms": 0.001,
    "s": 1.0,
    "sec": 1.0,
    "secs": 1.0,
    "m": 60.0,
    "min": 60.0,
    "mins": 60.0,
    "h": 3600.0,
    "hr": 3600.0,
    "hrs": 3600.0,
    "d": 86400.0,
}

_KEYWORD_VALUE_HINT = (
    "AND", "OR", "NOT", "BEFORE", "AFTER", "WITHIN", "LAST",
)


class Parser:
    def __init__(self, source: str, tokens: list[Token] | None = None) -> None:
        self.source = source
        self.tokens = tokens if tokens is not None else tokenize(source)
        self.pos = 0

    # -- token 辅助 -----------------------------------------------------
    def peek(self, offset: int = 0) -> Token:
        idx = min(self.pos + offset, len(self.tokens) - 1)
        return self.tokens[idx]

    def advance(self) -> Token:
        tok = self.tokens[self.pos]
        if tok.type != TokenType.EOF:
            self.pos += 1
        return tok

    def check(self, *types: str) -> bool:
        return self.peek().type in types

    def _err(
        self,
        tok: Token,
        message: str,
        hint: str | None = None,
        *,
        length: int | None = None,
    ) -> TQLSyntaxError:
        span = tok.span
        if length is not None and length != tok.length:
            span = Span(tok.offset, tok.line, tok.column, length)
        return TQLSyntaxError(message, source=self.source, span=span, hint=hint)

    def _expect(self, ttype: str, message: str, hint: str | None = None) -> Token:
        tok = self.peek()
        if tok.type != ttype:
            raise self._err(tok, message, hint)
        return self.advance()

    # -- 入口 -----------------------------------------------------------
    def parse(self) -> ast.Node | None:
        if self.peek().type == TokenType.EOF:
            return None
        expr = self.parse_or()
        tok = self.peek()
        if tok.type != TokenType.EOF:
            raise self._err(
                tok,
                f"查询解析完成后仍有意外输入 {tok.text!r}",
                "条件之间需要用 AND 或 OR 连接，例如 host=\"web-01\" AND level=\"error\"",
            )
        return expr

    # -- 表达式 ---------------------------------------------------------
    def parse_or(self) -> ast.Node:
        left = self.parse_and()
        nodes = [left]
        op_spans: list[Span] = []
        while self.check(TokenType.OR):
            op_tok = self.advance()
            right = self.parse_and()
            op_spans.append(op_tok.span)
            left = ast.LogicalExpr(
                span=self._merge_span(nodes[0], right),
                op="or",
                left=left,
                right=right,
                op_span=op_tok.span,
            )
        return left

    def parse_and(self) -> ast.Node:
        left = self.parse_unary()
        while self.check(TokenType.AND):
            op_tok = self.advance()
            right = self.parse_unary()
            left = ast.LogicalExpr(
                op="and", left=left, right=right, op_span=op_tok.span,
                span=self._merge_span(left, right),
            )
        return left

    def parse_unary(self) -> ast.Node:
        if self.check(TokenType.NOT):
            tok = self.advance()
            expr = self.parse_unary()
            return ast.NotExpr(expr=expr, span=self._merge_span_tok(tok, expr))
        return self.parse_temporal()

    def parse_temporal(self) -> ast.Node:
        left = self.parse_primary()
        if self.check(TokenType.BEFORE, TokenType.AFTER):
            dir_tok = self.advance()
            if self.check(TokenType.WITHIN):
                tok = self.peek()
                raise self._err(
                    tok,
                    f"{dir_tok.text.upper()} 之后缺少参照事件表达式",
                    f"正确形式：<事件条件> {dir_tok.text.upper()} <参照条件> [WITHIN 5m]",
                )
            right = self.parse_primary()
            within_seconds = None
            within_span = None
            if self.check(TokenType.WITHIN):
                w_tok = self.advance()
                dur_tok, within_seconds = self.parse_duration(context="WITHIN")
                within_span = self._merge_spans(w_tok.span, dur_tok.span)
            return ast.TemporalExpr(
                left=left,
                direction=dir_tok.type,  # type: ignore[arg-type]
                right=right,
                within_seconds=within_seconds,
                direction_span=dir_tok.span,
                within_span=within_span,
                span=self._merge_span(left, right),
            )
        if self.check(TokenType.WITHIN):
            tok = self.advance()
            raise self._err(
                tok,
                "WITHIN 时间窗口只能跟在 BEFORE / AFTER 关系之后",
                "例如 level=\"error\" AFTER #deploy WITHIN 10m；单独的最近窗口请用 LAST 15m",
            )
        return left

    # -- 原子条件 -------------------------------------------------------
    def parse_primary(self) -> ast.Node:
        tok = self.peek()

        if tok.type == TokenType.LPAREN:
            self.advance()
            expr = self.parse_or()
            close = self.peek()
            if close.type != TokenType.RPAREN:
                raise self._err(
                    close,
                    "括号内表达式之后缺少右括号 ')'",
                    "检查括号是否成对出现",
                )
            self.advance()
            expr.span = self._merge_span_tok(tok, close)
            return expr

        if tok.type == TokenType.LAST:
            self.advance()
            dur_tok, seconds = self.parse_duration(context="LAST")
            return ast.LastWindow(
                seconds=seconds,
                duration_span=dur_tok.span,
                span=self._merge_spans(tok.span, dur_tok.span),
            )

        if tok.type == TokenType.IDENT and tok.text.lower() in ("all_tags", "any_tags"):
            return self.parse_tag_call(tok)

        if tok.type == TokenType.TAG:
            self.advance()
            return ast.TagPredicate(tag=str(tok.value), span=tok.span)

        if tok.type == TokenType.IDENT:
            return self.parse_field_predicate(tok)

        raise self._err(
            tok,
            f"意外的 token {tok.text!r}" if tok.type != TokenType.EOF else "表达式未写完，意外到达输入末尾",
            "这里期望字段条件（如 host=\"web-01\"）、#标签、LAST 15m 或括号表达式",
        )

    def parse_field_predicate(self, field_tok: Token) -> ast.Node:
        self.advance()  # 字段名
        op_tok = self.peek()
        op_map = {
            TokenType.EQ: "=",
            TokenType.NE: "!=",
            TokenType.LT: "<",
            TokenType.LE: "<=",
            TokenType.GT: ">",
            TokenType.GE: ">=",
            TokenType.CONTAINS: "~",
            TokenType.NOT_CONTAINS: "!~",
        }
        op = op_map.get(op_tok.type)
        if op is None:
            if op_tok.type == TokenType.EOF:
                raise self._err(
                    op_tok,
                    f"字段 {field_tok.text!r} 后面缺少比较运算符",
                    "支持 =、!=、~（包含）、!~（不包含）、>、>=、<、<=",
                )
            if op_tok.type in (TokenType.STRING, TokenType.NUMBER, TokenType.IDENT,
                               TokenType.TAG):
                raise self._err(
                    op_tok,
                    f"字段 {field_tok.text!r} 后面缺少比较运算符",
                    "支持 =、!=、~（包含）、!~（不包含）、>、>=、<、<=",
                )
            raise self._err(
                op_tok,
                f"字段 {field_tok.text!r} 后面期望比较运算符，但遇到 {op_tok.text!r}",
                "支持 =、!=、~（包含）、!~（不包含）、>、>=、<、<=",
            )
        self.advance()

        value_tok = self.peek()
        value = self.parse_value(value_tok)
        return ast.FieldPredicate(
            field=field_tok.text.lower(),
            op=op,
            value=value,
            span=self._merge_spans(field_tok.span, value_tok.span),
            field_span=field_tok.span,
            op_span=op_tok.span,
            value_span=value_tok.span,
        )

    def parse_value(self, tok: Token) -> object:
        """读取比较值；失败直接抛语法错误。"""
        if tok.type == TokenType.STRING:
            self.advance()
            return tok.value
        if tok.type == TokenType.NUMBER:
            self.advance()
            return tok.value
        if tok.type == TokenType.IDENT:
            self.advance()
            return tok.text
        if tok.type in (TokenType.TAG,):
            self.advance()
            return str(tok.value)
        if tok.text and tok.text.upper() in _KEYWORD_VALUE_HINT:
            raise self._err(
                tok,
                f"{tok.text.upper()} 是查询关键字，不能直接作为比较值",
                f"如果确实要匹配文本 {tok.text!r}，请加引号：\"{tok.text}\"",
            )
        if tok.type == TokenType.EOF:
            raise self._err(
                tok,
                "比较运算符后面缺少值",
                "例如 level = \"error\"",
            )
        raise self._err(
            tok,
            f"比较运算符后面期望字符串、数字或裸词，但遇到 {tok.text!r}",
            "文本值建议加引号，例如 host = \"web-01\"",
        )

    def parse_tag_call(self, name_tok: Token) -> ast.TagListPredicate:
        mode = "all" if name_tok.text.lower().startswith("all") else "any"
        self.advance()
        self._expect(TokenType.LPAREN, f"{name_tok.text} 后面需要 '('")
        tags: list[str] = []
        if self.check(TokenType.RPAREN):
            rp = self.advance()
            raise self._err(rp, f"{name_tok.text}() 至少需要一个标签",
                            '例如 all_tags("deploy", "rca")')
        while True:
            tok = self.peek()
            if tok.type in (TokenType.STRING, TokenType.IDENT):
                self.advance()
                tags.append(str(tok.value if tok.type == TokenType.STRING else tok.text))
            elif tok.type == TokenType.TAG:
                self.advance()
                tags.append(str(tok.value))
            else:
                raise self._err(tok, "标签名应为引号字符串，例如 \"deploy\"")
            if self.check(TokenType.COMMA):
                self.advance()
                if self.check(TokenType.RPAREN):
                    rp = self.peek()
                    raise self._err(rp, "逗号后缺少标签名", "删除多余的逗号或补上标签")
                continue
            break
        rp = self._expect(TokenType.RPAREN, "标签列表之后缺少 ')'")
        return ast.TagListPredicate(
            mode=mode,  # type: ignore[arg-type]
            tags=tuple(t.lower() for t in tags),
            span=self._merge_spans(name_tok.span, rp.span),
        )

    # -- 时长 -----------------------------------------------------------
    def parse_duration(self, *, context: str = "WITHIN") -> tuple[Token, float]:
        num_tok = self.peek()
        if num_tok.type != TokenType.NUMBER:
            if num_tok.type == TokenType.EOF:
                raise self._err(
                    num_tok,
                    f"{context} 后缺少时长",
                    "时长格式为数字加单位：500ms / 30s / 5m / 2h / 7d",
                )
            raise self._err(
                num_tok,
                f"{context} 后期望时长数字（如 5m），但遇到 {num_tok.text!r}",
                "时长格式为数字加单位：500ms / 30s / 5m / 2h / 7d",
            )
        self.advance()
        unit_tok = self.peek()
        if unit_tok.type != TokenType.IDENT:
            raise self._err(
                num_tok,
                f"时长 {num_tok.text} 缺少时间单位",
                f"{context} 的时长需要单位；支持 ms / s / m / h / d，例如 5m、2h、30s",
            )
        unit = unit_tok.text.lower()
        if unit not in _UNIT_SECONDS:
            raise self._err(
                unit_tok,
                f"未知时间单位 {unit_tok.text!r}",
                "支持单位 ms / s / m（分钟）/ h（小时）/ d（天）",
            )
        self.advance()
        seconds = float(num_tok.value) * _UNIT_SECONDS[unit]  # type: ignore[arg-type]
        merged = Token(
            TokenType.NUMBER,
            num_tok.text + unit_tok.text,
            num_tok.offset,
            num_tok.line,
            num_tok.column,
            unit_tok.offset + unit_tok.length - num_tok.offset,
            value=seconds,
        )
        return merged, seconds

    # -- Span 工具 ------------------------------------------------------
    @staticmethod
    def _merge_spans(a: Span, b: Span) -> Span:
        start = a.offset
        end = b.offset + b.length
        # 跨行时行列信息以起点为准
        return Span(start, a.line, a.column, max(end - start, a.length))

    def _merge_span(self, first: ast.Node, last: ast.Node) -> Span | None:
        if first.span and last.span:
            return self._merge_spans(first.span, last.span)
        return first.span or last.span

    def _merge_span_tok(self, first: Token, last: ast.Node) -> Span:
        if last.span:
            return self._merge_spans(first.span, last.span)
        return first.span


def parse(source: str) -> ast.Node | None:
    """解析 TQL 字符串；空白串返回 None（表示无条件）。"""
    return Parser(source).parse()
