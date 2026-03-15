# backend/services/crawler/parsers/sku_hints/case_fan.py
from __future__ import annotations

import re
from typing import Any

from ..shared_specs import build_title_desc_texts
from ..shared_specs import extract_limit_hint
from ..shared_specs import extract_model_hint as shared_extract_model_hint
from ..shared_specs import extract_warranty_years as _extract_warranty_years
from ..shared_specs import normalized_title_line

_MODEL_BUNDLE_SPLIT_RE = re.compile(r"\s+[+＋]\s+")

_SIZE_WITH_UNIT_RE = re.compile(r"(?<!\d)(\d+(?:\.\d+)?)\s*(cm|公分|mm)(?![A-Za-z0-9])", flags=re.IGNORECASE)
_KNOWN_SIZE_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])(80|92|120|140|160|180|200|240)(?![A-Za-z0-9])")
_THICK_WORD_RE = re.compile(r"厚|厚度|thick", flags=re.IGNORECASE)
_THICKNESS_RE = re.compile(r"(?:厚度?|thick)[^0-9]{0,4}(\d+(?:\.\d+)?)\s*(cm|公分|mm)", flags=re.IGNORECASE)

_RPM_RANGE_RE = re.compile(r"(?<!\d)(\d{3,5})\s*(?:~|～|-|－)\s*(\d{3,5})\s*RPM", flags=re.IGNORECASE)
_RPM_SINGLE_RE = re.compile(r"(?<!\d)(\d{3,5})\s*RPM", flags=re.IGNORECASE)

_PWM_RE = re.compile(r"(?<![A-Za-z0-9])PWM(?![A-Za-z0-9])", flags=re.IGNORECASE)
_FAN_CONN_RE = re.compile(r"(?<![A-Za-z0-9])(3|4)\s*-?\s*Pin(?![A-Za-z0-9])", flags=re.IGNORECASE)
_RGB_RE = re.compile(r"(?<![A-Za-z0-9])(A-?RGB|A\.RGB|ARGB|RGB)(?![A-Za-z0-9])", flags=re.IGNORECASE)
_RGB_5V3_RE = re.compile(r"(?:5V[^\n]{0,12}3\s*-?\s*Pin|3\s*-?\s*Pin[^\n]{0,12}5V)", flags=re.IGNORECASE)
_RGB_12V4_RE = re.compile(r"(?:12V[^\n]{0,12}4\s*-?\s*Pin|4\s*-?\s*Pin[^\n]{0,12}12V)", flags=re.IGNORECASE)

_WHITE_RE = re.compile(r"白色版|白色|(?<![A-Za-z0-9])白(?!金)")
_BLACK_RE = re.compile(r"黑色|(?<![A-Za-z0-9])黑(?!金)")

_BEARING_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"FDB", flags=re.IGNORECASE), "fdb"),
    (re.compile(r"HDB", flags=re.IGNORECASE), "hdb"),
    (re.compile(r"雙滾珠|double\s*ball|ball", flags=re.IGNORECASE), "double_ball"),
    (re.compile(r"rifle", flags=re.IGNORECASE), "rifle"),
    (re.compile(r"sleeve|油封", flags=re.IGNORECASE), "sleeve"),
    (re.compile(r"hydraulic|液壓|液態", flags=re.IGNORECASE), "hydraulic"),
]

_PACK_NUM_RE = re.compile(r"(?<!\d)(\d+)\s*(?:入|顆裝|pack|Pack|PACK)(?![A-Za-z0-9])")
_PACK_FAN_RE = re.compile(r"(?<!\d)(\d+)\s*風扇")

_CONTROLLER_INCLUDED_RE = re.compile(r"[+＋/／]\s*控制器|附控制器|含控制器|含遙控|附遙控|含控制盒|附集線器|含集線器")
_REVERSE_RE = re.compile(r"反向|reverse", flags=re.IGNORECASE)

_LIMIT_RE = re.compile(r"(限組裝|限購|限搭機|客訂|限量)")
_BUNDLE_RE = re.compile(r"(大全配|套裝|組合|bundle)", flags=re.IGNORECASE)

_ACCESSORY_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"控制器|controller", flags=re.IGNORECASE), "controller"),
    (re.compile(r"\bHUB\b|集線器|hub", flags=re.IGNORECASE), "hub"),
    (
        re.compile(
            r"擴充線|連接線|延長線|分接線|轉接線|1轉|1分|SST-CPF|PWM\s*擴充線|ARGB\s*連接線|風扇電源擴充線|cable|線材",
            flags=re.IGNORECASE,
        ),
        "cable",
    ),
    (re.compile(r"支架|固定架|bracket", flags=re.IGNORECASE), "bracket"),
    (re.compile(r"燈條|燈效套件|led\s*strip", flags=re.IGNORECASE), "led_strip"),
    (re.compile(r"模組", flags=re.IGNORECASE), "module"),
]

_FAN_WORD_RE = re.compile(r"風扇|(?<![A-Za-z0-9])fan(?![A-Za-z0-9])", flags=re.IGNORECASE)
_FAN_PACK_RE = re.compile(
    r"(?<!\d)(?:2|3)\s*風扇|三顆裝|雙風扇組|三風扇組|顆裝|pack|入|[+＋]",
    flags=re.IGNORECASE,
)
_CONTROLLER_REQ_RE = re.compile(r"需[^\n]{0,12}控制器|需搭配[^\n]{0,12}控制器")


def _model_head(text: str) -> str:
    line = normalized_title_line(text)
    return shared_extract_model_hint(
        line,
        strip_bracket_tags=True,
        bundle_split_re=_MODEL_BUNDLE_SPLIT_RE,
    ) or ""


def extract_case_fan_sku_hint(title: str) -> str | None:
    head = _model_head(title)
    return head or None


def _extract_size_mm(texts: list[str]) -> int | None:
    for text in texts:
        m = _KNOWN_SIZE_TOKEN_RE.search(text or "")
        if m:
            return int(m.group(1))
    for text in texts:
        for m in _SIZE_WITH_UNIT_RE.finditer(text or ""):
            val = float(m.group(1))
            unit = m.group(2).lower()
            window = (text or "")[max(0, m.start() - 6):min(len(text or ""), m.end() + 6)]
            if _THICK_WORD_RE.search(window):
                continue
            if unit in ("cm", "公分"):
                if not (6 <= val <= 25):
                    continue
                return int(round(val * 10))
            if 60 <= val <= 250:
                return int(round(val))
    return None


def _extract_thickness_mm(texts: list[str]) -> int | None:
    for text in texts:
        m = _THICKNESS_RE.search(text or "")
        if m:
            val = float(m.group(1))
            unit = m.group(2).lower()
            if unit in ("cm", "公分"):
                return int(round(val * 10))
            return int(round(val))
    return None


def _extract_rpm(texts: list[str]) -> tuple[int | None, int | None]:
    for text in texts:
        m = _RPM_RANGE_RE.search(text or "")
        if m:
            lo = int(m.group(1))
            hi = int(m.group(2))
            return (min(lo, hi), max(lo, hi))
    for text in texts:
        m = _RPM_SINGLE_RE.search(text or "")
        if m:
            val = int(m.group(1))
            return (val, val)
    return (None, None)


def _extract_bearing(texts: list[str]) -> str | None:
    for text in texts:
        for pat, label in _BEARING_RULES:
            if pat.search(text or ""):
                return label
    return None


def _extract_fan_connector(texts: list[str]) -> str | None:
    for text in texts:
        for m in _FAN_CONN_RE.finditer(text or ""):
            start, end = m.span()
            window = (text or "")[max(0, start - 10):min(len(text or ""), end + 10)]
            if re.search(r"5V|12V", window, flags=re.IGNORECASE):
                continue
            return f"{m.group(1)}pin"
    return None


def _extract_rgb_header(texts: list[str]) -> str | None:
    for text in texts:
        if _RGB_5V3_RE.search(text or ""):
            return "5v_3pin"
    for text in texts:
        if _RGB_12V4_RE.search(text or ""):
            return "12v_4pin"
    return None


def _extract_color(texts: list[str]) -> str | None:
    for text in texts:
        if _WHITE_RE.search(text or ""):
            return "white"
    for text in texts:
        if _BLACK_RE.search(text or ""):
            return "black"
    return None


def _extract_pack_count(texts: list[str]) -> int | None:
    mapping = {
        "單顆": 1,
        "單顆裝": 1,
        "雙顆": 2,
        "雙顆裝": 2,
        "雙風扇": 2,
        "三顆": 3,
        "三顆裝": 3,
        "三風扇": 3,
        "雙風扇組": 2,
        "三風扇組": 3,
    }
    for text in texts:
        for key, val in mapping.items():
            if key in (text or ""):
                return None if val > 10 else val
        m = _PACK_FAN_RE.search(text or "")
        if m:
            val = int(m.group(1))
            return None if val > 10 else val
        m = _PACK_NUM_RE.search(text or "")
        if m:
            val = int(m.group(1))
            return None if val > 10 else val
    return None


def _detect_accessory(texts: list[str]) -> tuple[bool, str | None]:
    bundle_context = False
    for text in texts:
        t = text or ""
        if _CONTROLLER_REQ_RE.search(t):
            continue
        pack_cnt = _extract_pack_count([t])
        fan_like = bool(_RPM_RANGE_RE.search(t) or _RPM_SINGLE_RE.search(t) or _PWM_RE.search(t) or (_extract_size_mm([t]) is not None) or ("風扇" in t))
        if pack_cnt is not None and fan_like:
            bundle_context = True
            break
    if bundle_context:
        return False, None
    for text in texts:
        t = text or ""
        if _CONTROLLER_REQ_RE.search(t):
            continue
        pack_cnt = _extract_pack_count([t])
        fan_like = bool(_RPM_RANGE_RE.search(t) or _RPM_SINGLE_RE.search(t) or _PWM_RE.search(t) or (_extract_size_mm([t]) is not None) or ("風扇" in t))
        bundle_like = (pack_cnt is not None) and fan_like
        for pat, kind in _ACCESSORY_RULES:
            if kind in ("controller", "hub") and bundle_like:
                continue
            if pat.search(t):
                return True, kind
    return False, None


def extract_case_fan_listing_hints(title: str, desc_lines: list[str] | None) -> tuple[str | None, dict[str, Any]]:
    line, desc, texts = build_title_desc_texts(title, desc_lines)

    sku_hint = extract_case_fan_sku_hint(line)

    is_accessory, accessory_kind_hint = _detect_accessory(texts)

    rgb_hint = True if any(_RGB_RE.search(t or "") for t in texts) else None
    rgb_header_hint = _extract_rgb_header(texts)
    pwm_hint = True if any(_PWM_RE.search(t or "") for t in texts) else None
    fan_connector_hint = _extract_fan_connector(texts)
    color_hint = _extract_color(texts)
    pack_count_hint = _extract_pack_count(texts)
    reverse_fan_hint = True if any(_REVERSE_RE.search(t or "") for t in texts) else None
    warranty_years = _extract_warranty_years(texts)
    limit_hint = extract_limit_hint(texts, _LIMIT_RE)
    is_bundle = True if any(_BUNDLE_RE.search(t or "") for t in texts) else None

    fan_size_mm_hint = None
    fan_thickness_mm_hint = None
    rpm_min_hint = None
    rpm_max_hint = None
    bearing_hint = None
    controller_included_hint = None

    if not is_accessory:
        fan_size_mm_hint = _extract_size_mm(texts)
        fan_thickness_mm_hint = _extract_thickness_mm(texts)
        rpm_min_hint, rpm_max_hint = _extract_rpm(texts)
        bearing_hint = _extract_bearing(texts)
        controller_included_hint = True if any(_CONTROLLER_INCLUDED_RE.search(t or "") for t in texts) else None

    extra: dict[str, Any] = {
        "fan_size_mm_hint": fan_size_mm_hint,
        "fan_thickness_mm_hint": fan_thickness_mm_hint,
        "rpm_min_hint": rpm_min_hint,
        "rpm_max_hint": rpm_max_hint,
        "pwm_hint": pwm_hint,
        "fan_connector_hint": fan_connector_hint,
        "rgb_hint": rgb_hint,
        "rgb_header_hint": rgb_header_hint,
        "color_hint": color_hint,
        "bearing_hint": bearing_hint,
        "pack_count_hint": pack_count_hint,
        "controller_included_hint": controller_included_hint,
        "reverse_fan_hint": reverse_fan_hint,
        "warranty_years": warranty_years,
        "limit_hint": limit_hint,
        "is_bundle": is_bundle,
        "is_accessory": True if is_accessory else None,
        "accessory_kind_hint": accessory_kind_hint,
    }
    return sku_hint, extra
