# backend/services/crawler/parsers/sku_hints/hdd.py
from __future__ import annotations

import re

from .common import first_line, head_before_brackets, normalize_spaces, strip_leading_note

_CAPACITY_RE = re.compile(
    r"(?i)(?<!\d)(?P<num>\d+(?:\.\d+)?)\s*(?P<unit>TB|T|GB|G)(?![A-Za-z0-9])"
)
_RPM_RE = re.compile(r"(?P<rpm>\d{4,5})\s*轉")
_CACHE_MB_RE = re.compile(r"(?i)(?P<mb>\d{2,4})\s*MB\b")
_CACHE_M_RE = re.compile(r"(?i)(?P<mb>\d{2,4})\s*M\b")
_FORM_25_RE = re.compile(r"2\.5吋|2\.5\"", flags=re.IGNORECASE)
_FORM_35_RE = re.compile(r"3\.5吋|3\.5\"", flags=re.IGNORECASE)
_THICKNESS_RE = re.compile(r"(?i)(?P<mm>\d+(?:\.\d+)?)\s*mm\b")
_SATA_RE = re.compile(r"(?i)\bSATA\b")
_SAS_RE = re.compile(r"(?i)\bSAS\b")
_USB_RE = re.compile(r"(?i)\bUSB\b|Type-?C")
_SERIES_RE = re.compile(r"【(?P<text>[^】]+)】")
_LIMIT_RE = re.compile(r"(限組裝|限購)")
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
    re.compile(r"\bMQ[0-9A-Z]+\b", flags=re.IGNORECASE),
    re.compile(r"\bMG[0-9A-Z]+\b", flags=re.IGNORECASE),
]

_SEGMENT_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"企業|EXOS|Ultrastar", flags=re.IGNORECASE), "Enterprise"),
    (re.compile(r"監控|SkyHawk|監控鷹", flags=re.IGNORECASE), "Surveillance"),
    (re.compile(r"\bNAS\b|那嘶狼|IronWolf", flags=re.IGNORECASE), "NAS"),
    (re.compile(r"新梭魚|Barracuda|桌機|藍標", flags=re.IGNORECASE), "Desktop"),
]


def _extract_capacity_gib(text: str) -> int | None:
    m = _CAPACITY_RE.search(text or "")
    if not m:
        return None
    num = float(m.group("num"))
    unit = m.group("unit").upper()
    if unit in ("T", "TB"):
        bytes_val = num * 10**12
    else:
        bytes_val = num * 10**9
    return int(round(bytes_val / (1 << 30)))


def _extract_model_token(text: str) -> str | None:
    if not text:
        return None
    for m in _SERIES_RE.finditer(text):
        block = m.group("text")
        for pat in _MODEL_PATTERNS:
            hit = pat.search(block)
            if hit:
                return hit.group(0)
    for pat in _MODEL_PATTERNS:
        hit = pat.search(text)
        if hit:
            return hit.group(0)
    return None


def _extract_series_hint(text: str) -> str | None:
    m = _SERIES_RE.search(text or "")
    return m.group("text") if m else None


def _extract_segment_hint(text: str) -> str | None:
    for pat, label in _SEGMENT_RULES:
        if pat.search(text or ""):
            return label
    return None


def _extract_warranty_years(text: str) -> int | None:
    m = _WARRANTY_RE.search(text or "")
    if m:
        return int(m.group("yrs"))
    m = _WARRANTY_RES_PAIR_RE.search(text or "")
    if m:
        return int(m.group("w"))
    m = _WARRANTY_SLASH_RE.search(text or "")
    if m:
        return int(m.group("yrs"))
    return None


def _extract_rescue_years(text: str) -> int | None:
    m = _RESCUE_RE.search(text or "")
    return int(m.group("yrs")) if m else None


def _infer_brand(text: str) -> str | None:
    if _SEAGATE_RE.search(text or ""):
        return "SEAGATE"
    if _WD_RE.search(text or ""):
        return "WD"
    if _TOSHIBA_RE.search(text or ""):
        return "TOSHIBA"
    return None


def extract_hdd_sku_hint(title: str) -> str | None:
    line = normalize_spaces(strip_leading_note(first_line(title)))
    return _extract_model_token(line)


def extract_hdd_hints(title: str) -> tuple[str | None, dict[str, object]]:
    """
    「extra 會回傳完整欄位；但在上游輸出 JSON 時可能會做 compact（移除 None 的 key）。
    """
    text = title or ""
    line = normalize_spaces(strip_leading_note(first_line(text)))
    head = head_before_brackets(line)

    brand_hint = _infer_brand(head or line)
    model_hint = _extract_model_token(line)
    sku_hint = model_hint

    capacity_gib = _extract_capacity_gib(head) or _extract_capacity_gib(line)

    rpm_hint = None
    rpm_m = _RPM_RE.search(line)
    if rpm_m:
        rpm_hint = int(rpm_m.group("rpm"))

    cache_mb_hint = None
    cache_m = _CACHE_MB_RE.search(line)
    if cache_m:
        cache_mb_hint = int(cache_m.group("mb"))
    else:
        cache_m = _CACHE_M_RE.search(line)
        if cache_m:
            cache_mb_hint = int(cache_m.group("mb"))

    form_factor_hint = None
    if _FORM_25_RE.search(line):
        form_factor_hint = '2.5"'
    elif _FORM_35_RE.search(line):
        form_factor_hint = '3.5"'

    thickness_mm_hint = None
    if form_factor_hint == '2.5"':
        t_m = _THICKNESS_RE.search(line)
        if t_m:
            thickness_mm_hint = float(t_m.group("mm"))
            if thickness_mm_hint.is_integer():
                thickness_mm_hint = int(thickness_mm_hint)

    interface_hint = None
    if _SATA_RE.search(line):
        interface_hint = "SATA"
    elif _SAS_RE.search(line):
        interface_hint = "SAS"
    elif _USB_RE.search(line):
        interface_hint = "USB"

    series_hint = _extract_series_hint(line)
    segment_hint = _extract_segment_hint(line)
    rescue_years = _extract_rescue_years(line)
    warranty_years = _extract_warranty_years(line)

    limit_hint = None
    limit_m = _LIMIT_RE.search(line)
    if limit_m:
        limit_hint = limit_m.group(1)

    extra = {
        "brand_hint": brand_hint,
        "model_hint": model_hint,
        "capacity_gib": capacity_gib,
        "form_factor_hint": form_factor_hint,
        "thickness_mm_hint": thickness_mm_hint,
        "interface_hint": interface_hint,
        "rpm_hint": rpm_hint,
        "cache_mb_hint": cache_mb_hint,
        "series_hint": series_hint,
        "segment_hint": segment_hint,
        "rescue_years": rescue_years,
        "warranty_years": warranty_years,
        "limit_hint": limit_hint,
    }
    return sku_hint, extra
