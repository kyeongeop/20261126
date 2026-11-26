"""TQL 错误类型：所有错误都带行/列/片段，可渲染带插入符的提示。"""

from __future__ import annotations

from dataclasses import dataclass
import unicodedata


@dataclass(frozen=True)
class Span:
    """源码中的一段区间（偏移 0 基，行列 1 基）。"""

    offset: int
    line: int
    column: int
    length: int = 1

    @property
    def end_column(self) -> int:
        return self.column + max(self.length, 1)


def _char_width(ch: str) -> int:
    """字符在等宽终端里的显示宽度（CJK / 全角为 2）。"""
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def display_width(text: str) -> int:
    return sum(_char_width(ch) for ch in text)


class TQLError(Exception):
    """查询语言相关错误的基类。

    :param message: 人类可读的错误说明（中文）
    :param source: 原始查询串，用于渲染上下文行
    :param span: 出错片段的位置
    :param hint: 可选的修改建议
    """

    kind = "error"

    def __init__(
        self,
        message: str,
        *,
        source: str | None = None,
        span: Span | None = None,
        hint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.source = source
        self.span = span
        self.hint = hint

    # -- 便捷属性 -------------------------------------------------------
    @property
    def line(self) -> int | None:
        return self.span.line if self.span else None

    @property
    def column(self) -> int | None:
        return self.span.column if self.span else None

    @property
    def length(self) -> int:
        return self.span.length if self.span else 0

    @property
    def fragment(self) -> str:
        """出错的源码片段；EOF 处返回空串。"""
        if not self.source or not self.span:
            return ""
        start = self.span.offset
        end = min(start + max(self.span.length, 1), len(self.source))
        return self.source[start:end]

    # -- 渲染 -----------------------------------------------------------
    def _source_line(self) -> str:
        assert self.source is not None and self.span is not None
        lines = self.source.split("\n")
        idx = max(self.span.line - 1, 0)
        return lines[idx] if idx < len(lines) else ""

    def render(self) -> str:
        """渲染成类似编译器错误的多行文本，插入符精确指向列。"""
        head = f"{self.kind_label}（{self.kind}）：{self.message}"
        if not self.span or self.source is None:
            return head + (f"\n提示: {self.hint}" if self.hint else "")

        src_line = self._source_line()
        # 列 -> 该行起始偏移，用于计算插入符前的显示宽度
        prefix_chars = src_line[: max(self.span.column - 1, 0)]
        padding = " " * display_width(prefix_chars)
        frag = self.fragment or "^"
        caret_width = max(display_width(frag.strip("\n")) or 1, 1)
        caret = "^" * min(max(self.span.length, 1), caret_width)
        if self.span.length <= 1:
            caret = "^"

        gutter = f" {self.span.line} | "
        lines = [
            f"{head}  (第 {self.span.line} 行, 第 {self.span.column} 列)",
            f"{gutter}{src_line}",
            f" {' ' * len(str(self.span.line))} | {padding}{caret}",
        ]
        if self.hint:
            lines.append(f"提示: {self.hint}")
        return "\n".join(lines)

    @property
    def kind_label(self) -> str:
        return {"syntax": "TQL 语法错误", "semantic": "TQL 语义错误"}.get(
            self.kind, "TQL 查询错误"
        )

    def to_dict(self) -> dict:
        span = self.span
        return {
            "kind": self.kind,
            "type": self.__class__.__name__,
            "message": self.message,
            "hint": self.hint,
            "line": span.line if span else None,
            "column": span.column if span else None,
            "end_column": span.end_column if span else None,
            "offset": span.offset if span else None,
            "length": span.length if span else 0,
            "fragment": self.fragment,
            "rendered": self.render(),
        }


class TQLSyntaxError(TQLError):
    kind = "syntax"


class TQLSemanticError(TQLError):
    kind = "semantic"
