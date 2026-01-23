# backend/services/crawler/parsers/sku_hints/common.py
from __future__ import annotations

import re

_BRACKET_SPLIT_RE = re.compile(r"[（(【]") # Chinese/Japanese parentheses and brackets
_SPACE_RE = re.compile(r"\s+") # Matches one or more whitespace characters
_LEADING_NOTE_RE = re.compile(r"^\[[^\]]+\]\s*") # Matches leading notes in square brackets, e.g., "[促銷] "


def first_line(text: str) -> str: # 從多行文字中取第一個「非空行」當作代表行。
    if not text:
        return ""
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return text.strip()


def normalize_spaces(text: str) -> str: # 將多個空白字元（包含全形空白）合併為一個半形空白，並去除前後空白。
    return _SPACE_RE.sub(" ", (text or "")).strip()


def head_before_brackets(text: str) -> str: # 取「遇到括號前」的字串當作 head，並做空白正規化。
    head = _BRACKET_SPLIT_RE.split(text or "", 1)[0]
    return normalize_spaces(head)


def strip_leading_note(text: str) -> str: # 移除開頭的 [xxx] 類註記。
    return _LEADING_NOTE_RE.sub("", (text or "")).strip()
