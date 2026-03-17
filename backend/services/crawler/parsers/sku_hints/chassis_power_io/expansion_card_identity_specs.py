# backend/services/crawler/parsers/sku_hints/chassis_power_io/expansion_card_identity_specs.py
from __future__ import annotations

import re

from ..common import head_before_brackets, normalize_spaces
from ..shared_specs import extract_brand_hint as shared_extract_brand_hint
from ..shared_specs import extract_model_hint as shared_extract_model_hint
from ..shared_specs import normalized_title_line
from ..shared_specs import strip_leading_bracket_tags

_MODEL_BUNDLE_SPLIT_RE = re.compile(r"\s*[+＋]\s*")
_SPEC_CLEAN_RE = re.compile(
    r"(?<![A-Za-z0-9])PCI-?E(?![A-Za-z0-9])|(?<![A-Za-z0-9])PCIE(?![A-Za-z0-9])"
    r"|(?<![A-Za-z0-9])GEN\s*[345](?![A-Za-z0-9])|(?<![A-Za-z0-9])X\s*(?:1|4|8|16)(?![A-Za-z0-9])"
    r"|(?<![A-Za-z0-9])\d{1,3}\s*Gbps(?![A-Za-z0-9])|(?<![A-Za-z0-9])\d+\s*埠"
    r"|(?:\*|×)\s*\d+|(?<![A-Za-z0-9])x\s*\d+",
    flags=re.IGNORECASE,
)
_TAIL_MODEL_BRACKET_RE = re.compile(r"【\s*([A-Z0-9][A-Z0-9-]{3,})\s*】")
_HYPER_M2_RE = re.compile(r"HYPER\s*M\.2", flags=re.IGNORECASE)
_HYPER_GEN_RE = re.compile(r"GEN\s*([45])", flags=re.IGNORECASE)
_CJK_BRAND_ONLY_RE = re.compile(r"^[\u4e00-\u9fff]{1,6}$")
_BRAND_IGNORE = {
    "PCI",
    "PCIE",
    "USB",
    "USB4",
    "NVME",
    "SSD",
    "SATA",
    "RS232",
    "PARALLEL",
    "GEN",
    "CARD",
    "TYPE",
    "DP",
    "TB4",
    "TB5",
}


def _model_head(text: str) -> str:
    line = strip_leading_bracket_tags(normalized_title_line(text))
    has_bracket = bool(re.search(r"[（(【]", line))
    head = shared_extract_model_hint(line, bundle_split_re=_MODEL_BUNDLE_SPLIT_RE)
    if has_bracket and head and not _SPEC_CLEAN_RE.search(head):
        return head
    cleaned = shared_extract_model_hint(
        line,
        bundle_split_re=_MODEL_BUNDLE_SPLIT_RE,
        clean_pattern=_SPEC_CLEAN_RE,
    )
    return cleaned or head


def _tail_model_token(text: str) -> str | None:
    last: re.Match[str] | None = None
    for match in _TAIL_MODEL_BRACKET_RE.finditer(text or ""):
        last = match
    if not last:
        return None
    trailing = (text[last.end() :] if text else "").strip()
    if trailing and trailing not in {")", "）"}:
        return None
    return last.group(1)


def _hyper_gen_suffix(text: str) -> str | None:
    if not _HYPER_M2_RE.search(text or ""):
        return None
    match = _HYPER_GEN_RE.search(text or "")
    if not match:
        return None
    return f"GEN {match.group(1)}"


def extract_expansion_card_model_hint(title: str) -> str | None:
    line = strip_leading_bracket_tags(normalized_title_line(title))
    head = _model_head(line)
    tail_model = _tail_model_token(line)
    if head:
        if tail_model and _CJK_BRAND_ONLY_RE.fullmatch(head):
            return f"{head} {tail_model}"
        hyper_gen = _hyper_gen_suffix(line)
        if hyper_gen and hyper_gen not in head.upper():
            head = f"{head} {hyper_gen}"
        return head
    fallback = normalize_spaces(head_before_brackets(line) or line)
    if tail_model and _CJK_BRAND_ONLY_RE.fullmatch(fallback):
        return f"{fallback} {tail_model}"
    return fallback or line or None


def extract_expansion_card_brand_hint(text: str) -> str | None:
    return shared_extract_brand_hint(
        text,
        strip_bracket_tags=True,
        allow_cjk_prefix=True,
        ignore_tokens=_BRAND_IGNORE,
    )
