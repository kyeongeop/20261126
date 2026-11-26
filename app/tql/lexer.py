"""TQL 词法分析器：每个 Token 都保留偏移/行/列，供错误精确定位。"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import Span, TQLSyntaxError


class TokenType:
    EOF = "eof"
    IDENT = "ident"
    NUMBER = "number"
    STRING = "string"
    TAG = "tag"
    AND = "and"
    OR = "or"
    NOT = "not"
    BEFORE = "before"
    AFTER = "after"
    WITHIN = "within"
    LAST = "last"
    LPAREN = "lparen"
    RPAREN = "rparen"
    COMMA = "comma"
    EQ = "eq"
    NE = "ne"
    LT = "lt"
    LE = "le"
    GT = "gt"
    GE = "ge"
    CONTAINS = "contains"        # ~ 或 ~=
    NOT_CONTAINS = "not_contains"  # !~


KEYWORDS = {
    "and": TokenType.AND,
    "or": TokenType.OR,
    "not": TokenType.NOT,
    "before": TokenType.BEFORE,
    "after": TokenType.AFTER,
    "within": TokenType.WITHIN,
    "last": TokenType.LAST,
}


@dataclass
class Token:
    type: str
    text: str
    offset: int
    line: int
    column: int
    length: int
    value: object = None

    @property
    def span(self) -> Span:
        return Span(self.offset, self.line, self.column, self.length)


_TWO_CHAR_OPS = {
    "==": TokenType.EQ,
    "!=": TokenType.NE,
    "<>": TokenType.NE,
    "<=": TokenType.LE,
    ">=": TokenType.GE,
    "~=": TokenType.CONTAINS,
    "!~": TokenType.NOT_CONTAINS,
}
_ONE_CHAR_OPS = {
    "=": TokenType.EQ,
    "<": TokenType.LT,
    ">": TokenType.GT,
    "~": TokenType.CONTAINS,
}


class Lexer:
    def __init__(self, source: str) -> None:
        self.source = source
        self.n = len(source)
        self.i = 0
        self.line = 1
        self.line_start = 0

    # -- 基础 -----------------------------------------------------------
    def _col(self, offset: int) -> int:
        """给定绝对偏移，返回 1 基列号（基于当前扫描状态的行起点）。"""
        return offset - self.line_start + 1

    def _span_here(self, start: int, length: int) -> Span:
        return Span(start, self.line, start - self.line_start + 1, length)

    def _error(self, start: int, length: int, message: str, hint: str | None = None):
        # 错误可能发生在换行处理之后，调用处尽量在推进前构造
        line = self.line
        line_start = self.line_start
        # 若 start 位于上一行（字符串跨行场景），重新计算行/列
        if start < line_start:
            prefix = self.source[:start]
            line = prefix.count("\n") + 1
            last_nl = prefix.rfind("\n")
            line_start = last_nl + 1
        span = Span(start, line, start - line_start + 1, length)
        return TQLSyntaxError(message, source=self.source, span=span, hint=hint)

    def tokenize(self) -> list[Token]:
        tokens: list[Token] = []
        while self.i < self.n:
            ch = self.source[self.i]
            if ch in " \t\r":
                self.i += 1
                continue
            if ch == "\n":
                self.i += 1
                self.line += 1
                self.line_start = self.i
                continue
            start = self.i
            if ch == "#":
                tokens.append(self._read_tag(start))
            elif ch in "\"'":
                tokens.append(self._read_string(start, ch))
            elif ch.isdigit():
                tokens.append(self._read_number(start))
            elif ch.isalpha() or ch == "_":
                tokens.append(self._read_ident(start))
            elif ch == "(":
                self.i += 1
                tokens.append(Token(TokenType.LPAREN, "(", start, self.line,
                                    start - self.line_start + 1, 1))
            elif ch == ")":
                self.i += 1
                tokens.append(Token(TokenType.RPAREN, ")", start, self.line,
                                    start - self.line_start + 1, 1))
            elif ch == ",":
                self.i += 1
                tokens.append(Token(TokenType.COMMA, ",", start, self.line,
                                    start - self.line_start + 1, 1))
            else:
                tokens.append(self._read_operator(start))
        tokens.append(
            Token(
                TokenType.EOF,
                "",
                self.n,
                self.line,
                self.n - self.line_start + 1,
                1,
            )
        )
        return tokens

    # -- 各类 Token -----------------------------------------------------
    def _read_tag(self, start: int) -> Token:
        self.i += 1  # 吃掉 #
        name_start = self.i
        while self.i < self.n and self._is_tag_char(self.source[self.i]):
            self.i += 1
        if self.i == name_start:
            raise self._error(
                start,
                1,
                "标签语法 `#` 后缺少标签名",
                "例如 #deploy 或 #db-lock；也可以用 tag = \"deploy\"",
            )
        name = self.source[name_start : self.i]
        return Token(TokenType.TAG, self.source[start : self.i], start, self.line,
                     start - self.line_start + 1, self.i - start, value=name)

    @staticmethod
    def _is_tag_char(ch: str) -> bool:
        return ch.isalnum() or ch in "_-"

    def _read_string(self, start: int, quote: str) -> Token:
        self.i += 1
        value_chars: list[str] = []
        while self.i < self.n:
            ch = self.source[self.i]
            if ch == "\n":
                # 未闭合：片段划到行尾
                line_end = self.source.find("\n", start)
                if line_end == -1:
                    line_end = self.n
                raise self._error(
                    start,
                    max(line_end - start, 1),
                    "字符串缺少结束引号",
                    f"用 {quote} 闭合字符串，例如 {quote}error{quote}",
                )
            if ch == quote:
                self.i += 1
                text = self.source[start : self.i]
                return Token(TokenType.STRING, text, start, self.line,
                             start - self.line_start + 1, self.i - start,
                             value="".join(value_chars))
            if ch == "\\" and self.i + 1 < self.n:
                nxt = self.source[self.i + 1]
                escapes = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\",
                           quote: quote, "0": "\0"}
                value_chars.append(escapes.get(nxt, nxt))
                self.i += 2
                continue
            value_chars.append(ch)
            self.i += 1
        raise self._error(
            start,
            max(self.n - start, 1),
            "字符串缺少结束引号（到达输入末尾）",
            f"在值末尾补上 {quote}",
        )

    def _read_number(self, start: int) -> Token:
        while self.i < self.n and self.source[self.i].isdigit():
            self.i += 1
        is_float = False
        if self.i < self.n and self.source[self.i] == "." and (
            self.i + 1 < self.n and self.source[self.i + 1].isdigit()
        ):
            is_float = True
            self.i += 1
            while self.i < self.n and self.source[self.i].isdigit():
                self.i += 1
        text = self.source[start : self.i]
        value: object = float(text) if is_float else int(text)
        return Token(TokenType.NUMBER, text, start, self.line,
                     start - self.line_start + 1, self.i - start, value=value)

    def _read_ident(self, start: int) -> Token:
        # 允许裸值里出现 - 和 .，例如 web-01；首字符必须是字母/下划线
        while self.i < self.n:
            ch = self.source[self.i]
            if ch.isalnum() or ch in "_-.":
                self.i += 1
            else:
                break
        text = self.source[start : self.i]
        kw = KEYWORDS.get(text.lower())
        ttype = kw if kw else TokenType.IDENT
        return Token(ttype, text, start, self.line,
                     start - self.line_start + 1, self.i - start, value=text)

    def _read_operator(self, start: int) -> Token:
        two = self.source[start : start + 2]
        if two in _TWO_CHAR_OPS:
            self.i += 2
            return Token(_TWO_CHAR_OPS[two], two, start, self.line,
                         start - self.line_start + 1, 2)
        ch = self.source[start]
        if ch in _ONE_CHAR_OPS:
            self.i += 1
            return Token(_ONE_CHAR_OPS[ch], ch, start, self.line,
                         start - self.line_start + 1, 1)
        # 常见笔误给出针对性建议
        hint = None
        if ch == "!":
            hint = "不等于请写 !=，不包含请写 !~"
        elif ch == "&":
            hint = "逻辑与请使用 AND（不支持 &&）"
        elif ch == "|":
            hint = "逻辑或请使用 OR（不支持 ||）"
        elif ch == ";":
            hint = "一次只能执行一条 TQL 查询"
        raise self._error(start, 1, f"无法识别的字符 {ch!r}", hint)


def tokenize(source: str) -> list[Token]:
    return Lexer(source).tokenize()
