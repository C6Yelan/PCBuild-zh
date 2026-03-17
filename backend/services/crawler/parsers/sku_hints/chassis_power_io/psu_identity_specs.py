from __future__ import annotations

import re

from ..common import head_before_brackets, normalize_spaces
from ..shared_specs import extract_model_hint as shared_extract_model_hint
from ..shared_specs import normalized_title_line
from ..shared_specs import strip_leading_bracket_tags

_SPEC_CLEAN_RE = re.compile(
    r"ATX\s*3\.[01]|ATX3\.[01]|PCI-?E\s*5(?:\.[01])?|PCIE\s*5(?:\.[01])?"
    r"|80\s*\+?\s*(?:PLUS)?\s*(?:銅牌|銀牌|金牌|白金|鈦金|Bronze|Silver|Gold|Platinum|Titanium)"
    r"|銅牌|銀牌|金牌|白金|鈦金|Bronze|Silver|Gold|Platinum|Titanium"
    r"|\d+\s*年(?:保固|保)?|全日系|主日系|智慧停轉|停轉|0\s*RPM",
    flags=re.IGNORECASE,
)


def _clean_model_head(text: str) -> str:
    candidate = strip_leading_bracket_tags(text)
    candidate = re.sub(r"^([^\s(（【\[]+)[(（][^）)]{1,80}[)）]\s*", r"\1 ", candidate)
    return shared_extract_model_hint(candidate, clean_pattern=_SPEC_CLEAN_RE) or ""


def extract_psu_sku_hint(title: str) -> str | None:
    line = normalized_title_line(title)
    head = _clean_model_head(line)
    if head:
        return head
    fallback = normalize_spaces(head_before_brackets(strip_leading_bracket_tags(line)) or line)
    return fallback or None
