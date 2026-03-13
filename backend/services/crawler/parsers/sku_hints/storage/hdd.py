# backend/services/crawler/parsers/sku_hints/hdd.py
from __future__ import annotations

import re

from ..common import first_line, head_before_brackets, normalize_spaces, strip_leading_note

_CAPACITY_RE = re.compile( # 容量，支援 TB、GB 單位
    r"(?i)(?<!\d)(?P<num>\d+(?:\.\d+)?)\s*(?P<unit>TB|T|GB|G)(?![A-Za-z0-9])"
)
_RPM_RE = re.compile(r"(?P<rpm>\d{4,5})\s*轉") # 轉速, 單位 RPM
_CACHE_MB_RE = re.compile(r"(?i)(?P<mb>\d{2,4})\s*MB\b") # 快取容量, 單位 MB
_CACHE_M_RE = re.compile(r"(?i)(?P<mb>\d{2,4})\s*M\b") # 快取容量的備用模式, 單位 MB
_FORM_25_RE = re.compile(r"2\.5吋|2\.5\"", flags=re.IGNORECASE) # 用於識別 2.5 吋規格
_FORM_35_RE = re.compile(r"3\.5吋|3\.5\"", flags=re.IGNORECASE) # 用於識別 3.5 吋規格
_THICKNESS_RE = re.compile(r"(?i)(?P<mm>\d+(?:\.\d+)?)\s*mm\b") # 厚度, 單位 mm
_SATA_RE = re.compile(r"(?i)\bSATA\b") # 用於識別 SATA 規格
_SAS_RE = re.compile(r"(?i)\bSAS\b") # 用於識別 SAS(企業級) 規格
_USB_RE = re.compile(r"(?i)\bUSB\b|Type-?C") # 用於識別 USB 規格
_SERIES_RE = re.compile(r"【(?P<text>[^】]+)】") # 提取系列名稱
_LIMIT_RE = re.compile(r"(限組裝|限購)") # 用於識別限購或限組裝
_RESCUE_RE = re.compile(r"(?i)(?P<yrs>\d+)\s*年\s*Rescue") # 提取 Rescue 年限
_WARRANTY_RE = re.compile(r"(?P<yrs>\d+)\s*年保") # 提取保固年限
_WARRANTY_SLASH_RE = re.compile(r"/\s*(?P<yrs>\d+)\s*年\s*/") # 提取斜線分隔的保固年限
_WARRANTY_RES_PAIR_RE = re.compile(r"(?P<w>\d+)\s*年\s*/\s*(?P<r>\d+)\s*年\s*Rescue", flags=re.IGNORECASE) # 提取保固與 Rescue 年限對應組合

_SEAGATE_RE = re.compile(r"\bSeagate\b|希捷", flags=re.IGNORECASE)
_WD_RE = re.compile(r"\bWD\b|Western\s*Digital", flags=re.IGNORECASE)
_TOSHIBA_RE = re.compile(r"\bToshiba\b|東芝", flags=re.IGNORECASE)

_MODEL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bST[0-9A-Z]+\b", flags=re.IGNORECASE), # Seagate
    re.compile(r"\bWD[0-9A-Z]+\b", flags=re.IGNORECASE), # Western Digital
    re.compile(r"\bWUS[0-9A-Z]+\b", flags=re.IGNORECASE), # Western Digital Ultrastar
    re.compile(r"\bHDWR[0-9A-Z]+\b", flags=re.IGNORECASE), # Toshiba
    re.compile(r"\bHDWG[0-9A-Z]+\b", flags=re.IGNORECASE), # Toshiba
    re.compile(r"\bHDW[0-9A-Z]+\b", flags=re.IGNORECASE), # Toshiba
    # Toshiba: handle both "HDWR..." / "HDWG..." and spaced "HDW Dxxxx..."
    re.compile(r"\bHDW(?!R|G)\s*[0-9A-Z]+\b", flags=re.IGNORECASE),
    re.compile(r"\bMQ[0-9A-Z]+\b", flags=re.IGNORECASE), # Toshiba
    re.compile(r"\bMG[0-9A-Z]+\b", flags=re.IGNORECASE), # Toshiba
]

_SEGMENT_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"企業|EXOS|Ultrastar|金標|Gold", flags=re.IGNORECASE), "Enterprise"),
    (re.compile(r"監控|SkyHawk|監控鷹|紫標|Purple", flags=re.IGNORECASE), "Surveillance"),
    # note: don't use \\bNAS\\b because NAS碟 won't match under Unicode \\w rules
    (re.compile(r"NAS|那嘶狼|IronWolf|紅標|Red", flags=re.IGNORECASE), "NAS"),
    (re.compile(r"新梭魚|Barracuda|桌機|藍標|Blue", flags=re.IGNORECASE), "Desktop"),
]


def _pick_hint(*candidates: str | None) -> str:
    for cand in candidates:
        if cand is not None:
            s = str(cand).strip()
            if s != "":
                return s
    return ""


def _infer_brand_from_model_token(model_token: str | None) -> str | None:
    if model_token is None:
        return None
    token = model_token.strip().upper()
    if token == "":
        return None
    if token.startswith("ST"):
        return "SEAGATE"
    if token.startswith(("WD", "WUS")):
        return "WD"
    if token.startswith(("HDWR", "HDWG", "HDW", "MQ", "MG")):
        return "TOSHIBA"
    return None


def _extract_capacity_gib(text: str) -> int | None: # 提取容量並轉換為 GiB。
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


def _extract_model_token(text: str) -> str | None: # 提取型號提示。
    if not text:
        return None
    for m in _SERIES_RE.finditer(text):
        block = m.group("text")
        for pat in _MODEL_PATTERNS:
            hit = pat.search(block)
            if hit:
                return re.sub(r"\s+", "", hit.group(0))
    for pat in _MODEL_PATTERNS:
        hit = pat.search(text)
        if hit:
            return re.sub(r"\s+", "", hit.group(0))
    return None


def _extract_series_hint(text: str) -> str | None: # 提取系列提示。
    for m in _SERIES_RE.finditer(text or ""):
        t = (m.group("text") or "").strip()
        if not t:
            continue
        if t in ("限組裝", "限購", "監控型"):
            continue
        return t
    return None


def _extract_segment_hint(text: str) -> str | None: # 提取市場區隔提示。
    for pat, label in _SEGMENT_RULES:
        if pat.search(text or ""):
            return label
    return None


def _extract_warranty_years(text: str) -> int | None: #　提取保固年限。
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


def _extract_rescue_years(text: str) -> int | None: # 提取 Rescue 年限。
    m = _RESCUE_RE.search(text or "")
    return int(m.group("yrs")) if m else None


def _infer_brand(text: str) -> str | None: # 推斷品牌提示。
    if _SEAGATE_RE.search(text or ""):
        return "SEAGATE"
    if _WD_RE.search(text or ""):
        return "WD"
    if _TOSHIBA_RE.search(text or ""):
        return "TOSHIBA"
    return None


def extract_hdd_sku_hint(title: str) -> str | None: # 回傳 HDD 型號提示（sku_hint）。
    text = title or ""
    line = normalize_spaces(strip_leading_note(first_line(text)))
    head = head_before_brackets(line)
    model_token = _pick_hint(_extract_model_token(line), _extract_model_token(head), _extract_model_token(text))
    return _pick_hint(model_token, head, line, "UNKNOWN-HDD")


def extract_hdd_hints(title: str) -> tuple[str | None, dict[str, object]]:
    """
    「extra 會回傳完整欄位；但在上游輸出 JSON 時可能會做 compact（移除 None 的 key）。
    """
    text = title or ""
    line = normalize_spaces(strip_leading_note(first_line(text)))
    head = head_before_brackets(line)
    title_first_line = normalize_spaces(strip_leading_note(first_line(text)))

    model_token = _pick_hint(_extract_model_token(line), _extract_model_token(head), _extract_model_token(text))
    model_hint = _pick_hint(model_token, head, line, title_first_line, "UNKNOWN-HDD")
    sku_hint = _pick_hint(model_token, model_hint, head, line, title_first_line, "UNKNOWN-HDD")

    brand_hint = _infer_brand(head or line)
    if brand_hint is None:
        brand_hint = _infer_brand(text)
    if brand_hint is None:
        brand_hint = _infer_brand_from_model_token(model_token)
    if brand_hint is None:
        brand_hint = _infer_brand_from_model_token(model_hint)

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

    if interface_hint is None and form_factor_hint in ('2.5"', '3.5"'):
        interface_hint = "SATA"

    series_hint = _extract_series_hint(line)
    segment_hint = _extract_segment_hint(line)
    rescue_years = _extract_rescue_years(line)
    warranty_years = _extract_warranty_years(line)

    limit_hint = None
    limit_m = _LIMIT_RE.search(line)
    if limit_m:
        limit_hint = limit_m.group(1)

    extra = {
        "brand_hint": brand_hint, # 品牌提示
        "model_hint": model_hint, # 型號提示
        "capacity_gib": capacity_gib, # 容量提示，單位 GiB
        "form_factor_hint": form_factor_hint, # 規格提示（2.5"、3.5"）
        "thickness_mm_hint": thickness_mm_hint, # 厚度提示，單位 mm
        "interface_hint": interface_hint, # 介面提示（SATA、SAS、USB）
        "rpm_hint": rpm_hint, # 轉速提示，單位 RPM
        "cache_mb_hint": cache_mb_hint, # 快取容量提示，單位 MB
        "series_hint": series_hint, # 系列提示
        "segment_hint": segment_hint, # 市場區隔提示（桌機、NAS、企業等）
        "rescue_years": rescue_years, # Rescue 年限
        "warranty_years": warranty_years, # 保固年限
        "limit_hint": limit_hint, # 限購或限組裝提示
    }
    extra["model_hint"] = model_hint
    extra = {k: v for k, v in extra.items() if v is not None}
    return sku_hint, extra
