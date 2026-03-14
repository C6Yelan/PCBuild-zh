from __future__ import annotations

import html as _html
import re

_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style)\b.*?>.*?</\1>")
_BR_RE = re.compile(r"(?i)<br\s*/?>")
_DETAIL_DIV_RE = re.compile(r"(?is)<div\b[^>]*>(?P<text>.*?)</div>")


def to_text(fragment: str) -> str:
    fragment = _SCRIPT_STYLE_RE.sub(" ", fragment)
    fragment = _BR_RE.sub("\n", fragment)
    fragment = _TAG_RE.sub(" ", fragment)
    fragment = _html.unescape(fragment)
    fragment = re.sub(r"[ \t\u3000]+", " ", fragment)
    fragment = re.sub(r"\n{2,}", "\n", fragment)
    return fragment.strip()


def parse_int_price(value: str) -> int | None:
    normalized = (value or "").replace(",", "").strip()
    return int(normalized) if normalized.isdigit() else None


def extract_detail_lines(fragment: str) -> list[str]:
    lines: list[str] = []
    for match in _DETAIL_DIV_RE.finditer(fragment or ""):
        text = to_text(match.group("text"))
        if text:
            lines.append(text)
    return lines
