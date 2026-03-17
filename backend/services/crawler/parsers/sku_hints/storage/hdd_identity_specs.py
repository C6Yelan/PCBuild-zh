from __future__ import annotations

import re

from ..common import head_before_brackets
from ..shared_specs import normalized_title_line

_SERIES_RE = re.compile(r"【(?P<text>[^】]+)】")
_RESCUE_RE = re.compile(r"(?i)(?P<yrs>\d+)\s*年\s*Rescue")
_WARRANTY_RE = re.compile(r"(?P<yrs>\d+)\s*年保")
_WARRANTY_SLASH_RE = re.compile(r"/\s*(?P<yrs>\d+)\s*年\s*/")
_WARRANTY_RES_PAIR_RE = re.compile(r"(?P<w>\d+)\s*年\s*/\s*(?P<r>\d+)\s*年\s*Rescue", flags=re.IGNORECASE)
_SEAGATE_RE = re.compile(r"\bSeagate\b|希捷", flags=re.IGNORECASE)
_WD_RE = re.compile(r"\bWD\b|Western\s*Digital", flags=re.IGNORECASE)
_TOSHIBA_RE = re.compile(r"\bToshiba\b|東芝", flags=re.IGNORECASE)
_MODEL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bST[0-9A-Z]+\b", flags=re.IGNORECASE),
    re.compile(r"\bWD[0-9A-Z]+\b", flags=re.IGNORECASE),
    re.compile(r"\bWUS[0-9A-Z]+\b", flags=re.IGNORECASE),
    re.compile(r"\bHDWR[0-9A-Z]+\b", flags=re.IGNORECASE),
    re.compile(r"\bHDWG[0-9A-Z]+\b", flags=re.IGNORECASE),
    re.compile(r"\bHDW[0-9A-Z]+\b", flags=re.IGNORECASE),
    re.compile(r"\bHDW(?!R|G)\s*[0-9A-Z]+\b", flags=re.IGNORECASE),
    re.compile(r"\bMQ[0-9A-Z]+\b", flags=re.IGNORECASE),
    re.compile(r"\bMG[0-9A-Z]+\b", flags=re.IGNORECASE),
]
_SEGMENT_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"企業|EXOS|Ultrastar|金標|Gold", flags=re.IGNORECASE), "Enterprise"),
    (re.compile(r"監控|SkyHawk|監控鷹|紫標|Purple", flags=re.IGNORECASE), "Surveillance"),
    (re.compile(r"NAS|那嘶狼|IronWolf|紅標|Red", flags=re.IGNORECASE), "NAS"),
    (re.compile(r"新梭魚|Barracuda|桌機|藍標|Blue", flags=re.IGNORECASE), "Desktop"),
]


def _pick_hint(*candidates: str | None) -> str:
    for candidate in candidates:
        if candidate is not None:
            value = str(candidate).strip()
            if value:
                return value
    return ""


def infer_hdd_brand_from_model_token(model_token: str | None) -> str | None:
    if model_token is None:
        return None
    token = model_token.strip().upper()
    if not token:
        return None
    if token.startswith("ST"):
        return "SEAGATE"
    if token.startswith(("WD", "WUS")):
        return "WD"
    if token.startswith(("HDWR", "HDWG", "HDW", "MQ", "MG")):
        return "TOSHIBA"
    return None


def extract_hdd_model_token(text: str) -> str | None:
    if not text:
        return None
    for match in _SERIES_RE.finditer(text):
        block = match.group("text")
        for pattern in _MODEL_PATTERNS:
            hit = pattern.search(block)
            if hit:
                return re.sub(r"\s+", "", hit.group(0))
    for pattern in _MODEL_PATTERNS:
        hit = pattern.search(text)
        if hit:
            return re.sub(r"\s+", "", hit.group(0))
    return None


def extract_hdd_series_hint(text: str) -> str | None:
    for match in _SERIES_RE.finditer(text or ""):
        value = (match.group("text") or "").strip()
        if not value or value in ("限組裝", "限購", "監控型"):
            continue
        return value
    return None


def extract_hdd_segment_hint(text: str) -> str | None:
    for pattern, label in _SEGMENT_RULES:
        if pattern.search(text or ""):
            return label
    return None


def extract_hdd_warranty_years(text: str) -> int | None:
    match = _WARRANTY_RE.search(text or "")
    if match:
        return int(match.group("yrs"))
    match = _WARRANTY_RES_PAIR_RE.search(text or "")
    if match:
        return int(match.group("w"))
    match = _WARRANTY_SLASH_RE.search(text or "")
    if match:
        return int(match.group("yrs"))
    return None


def extract_hdd_rescue_years(text: str) -> int | None:
    match = _RESCUE_RE.search(text or "")
    return int(match.group("yrs")) if match else None


def infer_hdd_brand(text: str) -> str | None:
    if _SEAGATE_RE.search(text or ""):
        return "SEAGATE"
    if _WD_RE.search(text or ""):
        return "WD"
    if _TOSHIBA_RE.search(text or ""):
        return "TOSHIBA"
    return None


def extract_hdd_sku_hint(title: str) -> str | None:
    text = title or ""
    line = normalized_title_line(text)
    head = head_before_brackets(line)
    model_token = _pick_hint(extract_hdd_model_token(line), extract_hdd_model_token(head), extract_hdd_model_token(text))
    return _pick_hint(model_token, head, line, "UNKNOWN-HDD")
