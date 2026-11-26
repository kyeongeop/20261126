"""Redaction engine: field-level rules, regex rules, and context exceptions.

Replacements are deterministic: the same sensitive value always maps to the
same pseudonym for a given rule label, derived from an HMAC of the value with
a persisted secret. Re-exporting the same event therefore yields identical
output.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

CONTEXT_WINDOW = 40


@dataclass(frozen=True)
class ContextException:
    """An exception that suppresses redaction.

    on="match":   skip when the matched text itself matches `pattern`.
    on="context": skip when the surrounding text (CONTEXT_WINDOW chars on
                  each side of the match) matches `pattern`.
    """

    pattern: str
    on: str = "match"

    def matches(self, matched_text: str, full_text: str, start: int, end: int) -> bool:
        if self.on == "match":
            return re.search(self.pattern, matched_text) is not None
        lo = max(0, start - CONTEXT_WINDOW)
        hi = min(len(full_text), end + CONTEXT_WINDOW)
        return re.search(self.pattern, full_text[lo:hi]) is not None


@dataclass(frozen=True)
class RegexRule:
    name: str
    label: str
    pattern: str
    exceptions: tuple[ContextException, ...] = ()


@dataclass(frozen=True)
class FieldRule:
    name: str
    label: str
    fields: tuple[str, ...]
    exceptions: tuple[ContextException, ...] = ()


@dataclass
class RedactionResult:
    data: Any
    counts: Counter = field(default_factory=Counter)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


class Redactor:
    def __init__(
        self,
        secret: bytes,
        regex_rules: list[RegexRule] | None = None,
        field_rules: list[FieldRule] | None = None,
    ) -> None:
        self._secret = secret
        self.regex_rules = regex_rules or []
        self.field_rules = field_rules or []

    def pseudonym(self, label: str, value: str) -> str:
        digest = hmac.new(
            self._secret, f"{label}:{value}".encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return f"<{label}:{digest[:10]}>"

    def redact(self, data: Any) -> RedactionResult:
        result = RedactionResult(data=None)
        result.data = self._walk(data, path="", result=result)
        return result

    def _walk(self, node: Any, path: str, result: RedactionResult) -> Any:
        if isinstance(node, dict):
            return {
                key: self._walk(value, f"{path}.{key}" if path else key, result)
                for key, value in node.items()
            }
        if isinstance(node, list):
            return [self._walk(item, path, result) for item in node]
        if isinstance(node, str):
            return self._redact_string(node, path, result)
        return node

    def _redact_string(self, text: str, path: str, result: RedactionResult) -> str:
        for rule in self.field_rules:
            if path in rule.fields:
                if self._excepted(rule.exceptions, text, text, 0, len(text)):
                    continue
                result.counts[rule.name] += 1
                return self.pseudonym(rule.label, text)
        for rule in self.regex_rules:
            text = self._apply_regex(rule, text, result)
        return text

    def _apply_regex(self, rule: RegexRule, text: str, result: RedactionResult) -> str:
        def replace(match: re.Match) -> str:
            matched = match.group(0)
            if self._excepted(rule.exceptions, matched, text, match.start(), match.end()):
                return matched
            result.counts[rule.name] += 1
            return self.pseudonym(rule.label, matched)

        return re.sub(rule.pattern, replace, text)

    @staticmethod
    def _excepted(
        exceptions: tuple[ContextException, ...],
        matched: str,
        full_text: str,
        start: int,
        end: int,
    ) -> bool:
        return any(exc.matches(matched, full_text, start, end) for exc in exceptions)
