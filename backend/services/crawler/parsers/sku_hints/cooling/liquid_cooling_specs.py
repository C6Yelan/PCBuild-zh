from __future__ import annotations

import re

from ..shared_specs import extract_brand_hint as shared_extract_brand_hint
from ..shared_specs import extract_model_hint as shared_extract_model_hint
from ..shared_specs import extract_warranty_years_with_registration
from ..shared_specs import normalize_length_mm

_RADIATOR_SIZE_RE = re.compile(r"(?<!\d)(120|240|280|360|420)(?!\d)")
_THICKNESS_MM_RE = re.compile(r"(?<!\d)(\d{2,3})\s*mm(?![A-Za-z0-9])", flags=re.IGNORECASE)
_THICKNESS_HINT_RE = re.compile(r"(厚排|厚冷排|加厚|厚[:：]?|厚)")
_THICKNESS_CM_RE = re.compile(r"厚[:：]\s*(\d+(?:\.\d+)?)\s*(?:cm)?", flags=re.IGNORECASE)
_FAN_RE = re.compile(r"(風扇|fan)", flags=re.IGNORECASE)
_LCD_RE = re.compile(r"(?<!\d)(\d+(?:\.\d+)?)\s*(?:吋|\")")

_ARGB_RE = re.compile(r"(?<![A-Za-z0-9])(A-?RGB|A\.RGB|ARGB|5V\s*3PIN)(?![A-Za-z0-9])", flags=re.IGNORECASE)
_RGB_RE = re.compile(r"(?<![A-Za-z0-9])RGB(?![A-Za-z0-9])", flags=re.IGNORECASE)
_DRGB_RE = re.compile(r"(?<![A-Za-z0-9])D-?RGB(?![A-Za-z0-9])", flags=re.IGNORECASE)

_LIMIT_RE = re.compile(r"(限組裝|限購|限量)")
_BUNDLE_RE = re.compile(r"(大全配|套裝|組合|bundle)", flags=re.IGNORECASE)
_ACCESSORY_RE = re.compile(r"(扣具|支架|轉接|控制器|延長線|套件|配件|管路|水冷液|水冷頭風扇)")
_ACCESSORY_NEG_RE = re.compile(r"(不含|未含|無含|不附|未附|無附)\s*控制器")

_REGISTER_RE = re.compile(r"註冊\s*(\d+)\s*\+\s*(\d+)\s*年?")

_BRAND_IGNORE = {"CPU", "PWM", "RGB", "ARGB", "AIO", "TDP", "M2", "SSD", "HDD", "LCD"}

_BRAND_PREFIX_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^利民"), "THERMALRIGHT"),
    (re.compile(r"^酷碼"), "COOLERMASTER"),
    (re.compile(r"^貓頭鷹"), "NOCTUA"),
    (re.compile(r"^喬思伯"), "JONSBO"),
    (re.compile(r"^九州風神"), "DEEPCOOL"),
    (re.compile(r"^銀欣"), "SILVERSTONE"),
    (re.compile(r"^全漢"), "FSP"),
    (re.compile(r"^保銳"), "ENERMAX"),
    (re.compile(r"^微星"), "MSI"),
    (re.compile(r"^華碩"), "ASUS"),
    (re.compile(r"^聯力"), "LIANLI"),
    (re.compile(r"^幾何未來"), "GEOMETRICFUTURE"),
    (re.compile(r"^旋剛"), "SHARKOON"),
    (re.compile(r"^技嘉"), "GIGABYTE"),
    (re.compile(r"^darkflash", flags=re.IGNORECASE), "DARKFLASH"),
    (re.compile(r"^montech", flags=re.IGNORECASE), "MONTECH"),
    (re.compile(r"^scythe", flags=re.IGNORECASE), "SCYTHE"),
    (re.compile(r"^cougar", flags=re.IGNORECASE), "COUGAR"),
]

_SOCKET_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?<![A-Za-z0-9])LGA\s*1700(?![A-Za-z0-9])", flags=re.IGNORECASE), "LGA1700"),
    (re.compile(r"(?<![A-Za-z0-9])LGA\s*1851(?![A-Za-z0-9])", flags=re.IGNORECASE), "LGA1851"),
    (re.compile(r"(?<![A-Za-z0-9])LGA\s*1200(?![A-Za-z0-9])", flags=re.IGNORECASE), "LGA1200"),
    (re.compile(r"(?<![A-Za-z0-9])LGA\s*115x(?![A-Za-z0-9])", flags=re.IGNORECASE), "LGA115x"),
    (re.compile(r"(?<![A-Za-z0-9])LGA\s*2066(?![A-Za-z0-9])", flags=re.IGNORECASE), "LGA2066"),
    (re.compile(r"(?<![A-Za-z0-9])LGA\s*4677(?![A-Za-z0-9])", flags=re.IGNORECASE), "LGA4677"),
    (re.compile(r"(?<![A-Za-z0-9])AM4(?![A-Za-z0-9])", flags=re.IGNORECASE), "AM4"),
    (re.compile(r"(?<![A-Za-z0-9])AM5(?![A-Za-z0-9])", flags=re.IGNORECASE), "AM5"),
    (re.compile(r"(?<![A-Za-z0-9])TR4(?![A-Za-z0-9])", flags=re.IGNORECASE), "TR4"),
    (re.compile(r"(?<![A-Za-z0-9])sTRX4(?![A-Za-z0-9])", flags=re.IGNORECASE), "sTRX4"),
    (re.compile(r"(?<![A-Za-z0-9])sTR5(?![A-Za-z0-9])", flags=re.IGNORECASE), "sTR5"),
    (re.compile(r"(?<![A-Za-z0-9])SP6(?![A-Za-z0-9])", flags=re.IGNORECASE), "SP6"),
]


def extract_liquid_cooling_brand_hint(text: str) -> str | None:
    return shared_extract_brand_hint(
        text,
        prefix_rules=_BRAND_PREFIX_RULES,
        ignore_tokens=_BRAND_IGNORE,
    )


def extract_liquid_cooling_model_hint(text: str) -> str | None:
    return shared_extract_model_hint(text)


def extract_liquid_cooling_spec_hints(text: str) -> dict[str, object]:
    return {
        "radiator_size_mm_hint": extract_liquid_cooling_radiator_size(text),
        "radiator_thickness_mm_hint": extract_liquid_cooling_radiator_thickness(text),
        "lcd_size_inch_hint": extract_liquid_cooling_lcd_size(text),
        "rgb_hint": extract_liquid_cooling_rgb_hint(text),
        "socket_support_hint": extract_liquid_cooling_sockets(text),
    }


def extract_liquid_cooling_warranty_years(texts: list[str]) -> int | None:
    return extract_warranty_years_with_registration(texts, _REGISTER_RE)


def extract_liquid_cooling_limit_hint(text: str) -> str | None:
    m = _LIMIT_RE.search(text or "")
    return m.group(1) if m else None


def infer_liquid_cooling_bundle(text: str) -> bool:
    return bool(_BUNDLE_RE.search(text or ""))


def extract_liquid_cooling_accessory_hint(text: str) -> bool:
    accessory_hit = bool(_ACCESSORY_RE.search(text or "")) and not bool(_ACCESSORY_NEG_RE.search(text or ""))
    return bool(accessory_hit and extract_liquid_cooling_radiator_size(text) is None)


def extract_liquid_cooling_radiator_size(text: str) -> int | None:
    m = _RADIATOR_SIZE_RE.search(text or "")
    return int(m.group(1)) if m else None


def extract_liquid_cooling_radiator_thickness(text: str) -> int | None:
    m = _THICKNESS_CM_RE.search(text or "")
    if m:
        return normalize_length_mm(float(m.group(1)), "cm")
    for m in _THICKNESS_MM_RE.finditer(text or ""):
        tail = (text or "")[m.end() : m.end() + 3]
        if _FAN_RE.search(tail):
            continue
        window = (text or "")[max(0, m.start() - 8) : min(len(text or ""), m.end() + 8)]
        if _THICKNESS_HINT_RE.search(window):
            return normalize_length_mm(float(m.group(1)), "mm")
    return None


def extract_liquid_cooling_lcd_size(text: str) -> float | None:
    m = _LCD_RE.search(text or "")
    if not m:
        return None
    return float(m.group(1))


def extract_liquid_cooling_rgb_hint(text: str) -> str | None:
    if _DRGB_RE.search(text or ""):
        return "d-rgb"
    if _ARGB_RE.search(text or ""):
        return "argb"
    if _RGB_RE.search(text or ""):
        return "rgb"
    return None


def extract_liquid_cooling_sockets(text: str) -> list[str] | None:
    found: set[str] = set()
    for pat, norm in _SOCKET_RULES:
        if pat.search(text or ""):
            found.add(norm)
    if not found:
        return None
    return sorted(found)


__all__ = [
    "extract_liquid_cooling_accessory_hint",
    "extract_liquid_cooling_brand_hint",
    "extract_liquid_cooling_limit_hint",
    "extract_liquid_cooling_model_hint",
    "extract_liquid_cooling_spec_hints",
    "extract_liquid_cooling_warranty_years",
    "infer_liquid_cooling_bundle",
]
