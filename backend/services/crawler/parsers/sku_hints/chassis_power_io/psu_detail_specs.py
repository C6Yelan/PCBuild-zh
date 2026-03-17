# backend/services/crawler/parsers/sku_hints/chassis_power_io/psu_detail_specs.py
from __future__ import annotations

import re

from ..common import normalize_spaces
from ..shared_specs import build_title_desc_texts
from ..shared_specs import extract_limit_hint
from ..shared_specs import extract_warranty_years
from .psu_identity_specs import extract_psu_sku_hint

_WATT_RE = re.compile(r"(?<![A-Za-z0-9])(\d{2,4})\s*W(?![A-Za-z0-9])", flags=re.IGNORECASE)
_ATX_VERSION_RE = re.compile(r"ATX\s*3\.(0|1)", flags=re.IGNORECASE)
_PCIE_VERSION_RE = re.compile(r"(?<![A-Za-z0-9])PCI-?E\s*5(?:\.(0|1))?(?![A-Za-z0-9])", flags=re.IGNORECASE)
_NATIVE_LINE_RE = re.compile(r"原生")
_NATIVE_2X6_RE = re.compile(r"12V-?2x6", flags=re.IGNORECASE)
_NATIVE_HPW_RE = re.compile(r"12V\s*HPWR", flags=re.IGNORECASE)
_NATIVE_12P4_RE = re.compile(r"12\s*\+\s*4", flags=re.IGNORECASE)
_NATIVE_COUNT_RE = re.compile(r"(?<!\d)(?:[x*＊]\s*)(\d+)", flags=re.IGNORECASE)
_PSU_LENGTH_RE = re.compile(r"電源長度\s*[:：]\s*(.+)")
_SFX_L_RE = re.compile(r"【?\s*SFX-?L\s*】?", flags=re.IGNORECASE)
_SFX_RE = re.compile(r"【?\s*SFX\s*】?", flags=re.IGNORECASE)
_ATX_FORM_RE = re.compile(r"ATX\s*(規格|電源)", flags=re.IGNORECASE)
_WHITE_RE = re.compile(r"白色版|白色|(?<![A-Za-z0-9])白(?!金)")
_BLACK_RE = re.compile(r"黑色|(?<![A-Za-z0-9])黑(?!金)")
_ZERO_RPM_RE = re.compile(r"智慧停轉|停轉|0\s*RPM", flags=re.IGNORECASE)
_CAPS_ALL_RE = re.compile(r"全日系")
_CAPS_MAIN_RE = re.compile(r"主日系")
_LIMIT_RE = re.compile(r"(限組裝|限購|限量|客訂)")
_BUNDLE_RE = re.compile(r"(大全配|套裝|組合|bundle)", flags=re.IGNORECASE)
_ACCESSORY_RE = re.compile(r"(延長線|套件|轉接|支架|扣具|配件|模組線|轉接線)")
_EFFICIENCY_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"鈦金|Titanium", flags=re.IGNORECASE), "titanium"),
    (re.compile(r"白金|Platinum", flags=re.IGNORECASE), "platinum"),
    (re.compile(r"金牌|Gold", flags=re.IGNORECASE), "gold"),
    (re.compile(r"銀牌|Silver", flags=re.IGNORECASE), "silver"),
    (re.compile(r"銅牌|Bronze", flags=re.IGNORECASE), "bronze"),
    (re.compile(r"80\s*\+", flags=re.IGNORECASE), "standard"),
]
_MODULAR_FULL_RE = re.compile(r"全模組|全模")
_MODULAR_SEMI_RE = re.compile(r"半模組|半模")
_MODULAR_NON_RE = re.compile(r"直出壓紋線|直出扁線|直出線")
_CABLE_FLAT_RE = re.compile(r"直出扁線|直出線\s*/\s*扁平線")
_CABLE_FIXED_RE = re.compile(r"直出壓紋線|直出線|壓紋線材|壓紋線")


def _extract_watt(texts: list[str]) -> int | None:
    watts: list[int] = []
    for text in texts:
        watts.extend(int(match.group(1)) for match in _WATT_RE.finditer(text or ""))
    return max(watts) if watts else None


def _extract_efficiency(text: str) -> str | None:
    for pattern, label in _EFFICIENCY_RULES:
        if pattern.search(text or ""):
            return label
    return None


def _extract_modular(text: str) -> str | None:
    if _MODULAR_NON_RE.search(text or ""):
        return "non"
    if _MODULAR_FULL_RE.search(text or ""):
        return "full"
    if _MODULAR_SEMI_RE.search(text or ""):
        return "semi"
    return None


def _extract_cable_type(text: str) -> str | None:
    if _CABLE_FLAT_RE.search(text or ""):
        return "flat_fixed"
    if _CABLE_FIXED_RE.search(text or ""):
        return "fixed"
    return None


def _extract_atx_version(texts: list[str]) -> str | None:
    for text in texts:
        match = _ATX_VERSION_RE.search(text or "")
        if match:
            return f"3.{match.group(1)}"
    return None


def _extract_pcie_version(text: str) -> str | None:
    found = False
    for match in _PCIE_VERSION_RE.finditer(text or ""):
        found = True
        if match.group(1) == "1":
            return "5.1"
    return "5.0" if found else None


def _extract_native_connector(lines: list[str], title: str) -> tuple[str | None, int | None]:
    candidates = list(lines)
    if title:
        candidates.append(title)
    for line in candidates:
        if not _NATIVE_LINE_RE.search(line or ""):
            continue
        hint = None
        if _NATIVE_2X6_RE.search(line):
            hint = "12v-2x6"
        elif _NATIVE_HPW_RE.search(line):
            hint = "12vhpwr"
        elif _NATIVE_12P4_RE.search(line):
            hint = "12+4"
        if not hint:
            continue
        counts = [int(match.group(1)) for match in _NATIVE_COUNT_RE.finditer(line)]
        return hint, max(counts) if counts else None
    return None, None


def _extract_psu_length(lines: list[str]) -> str | None:
    for line in lines:
        match = _PSU_LENGTH_RE.search(line)
        if match:
            length = normalize_spaces(match.group(1))
            return length or None
    return None


def _extract_form_factor(texts: list[str]) -> str | None:
    for text in texts:
        if _SFX_L_RE.search(text or ""):
            return "sfx-l"
        if _SFX_RE.search(text or ""):
            return "sfx"
    for text in texts:
        if _ATX_FORM_RE.search(text or ""):
            return "atx"
    return None


def _extract_color(text: str) -> str | None:
    if _WHITE_RE.search(text or ""):
        return "white"
    if _BLACK_RE.search(text or ""):
        return "black"
    return None


def _extract_caps_hint(text: str) -> str | None:
    if _CAPS_ALL_RE.search(text or ""):
        return "all_japanese"
    if _CAPS_MAIN_RE.search(text or ""):
        return "main_japanese"
    return None


def extract_psu_hints(title: str, desc_lines: list[str] | None = None) -> tuple[str | None, dict[str, object]]:
    line, desc, texts = build_title_desc_texts(title, desc_lines)
    sku_hint = extract_psu_sku_hint(line)

    watt_w_hint = _extract_watt(texts)
    efficiency_hint = _extract_efficiency(line)
    modular_hint = _extract_modular(line)
    cable_type_hint = _extract_cable_type(line)
    atx_version_hint = _extract_atx_version(texts)
    pcie_version_hint = _extract_pcie_version(line)
    native_12v_connector_hint, native_12v_connector_count_hint = _extract_native_connector(desc, line)
    psu_length_hint = _extract_psu_length(desc)
    form_factor_hint = _extract_form_factor(texts)
    color_hint = _extract_color(line)
    warranty_years = extract_warranty_years(texts)
    caps_hint = _extract_caps_hint(line)
    has_zero_rpm_hint = True if _ZERO_RPM_RE.search(line) else None
    limit_hint = extract_limit_hint([line], _LIMIT_RE)
    is_bundle = True if _BUNDLE_RE.search(line) else None
    is_accessory = True if (_ACCESSORY_RE.search(line) and watt_w_hint is None) else None

    extra: dict[str, object] = {
        "watt_w_hint": watt_w_hint,
        "efficiency_hint": efficiency_hint,
        "modular_hint": modular_hint,
        "cable_type_hint": cable_type_hint,
        "atx_version_hint": atx_version_hint,
        "pcie_version_hint": pcie_version_hint,
        "native_12v_connector_hint": native_12v_connector_hint,
        "native_12v_connector_count_hint": native_12v_connector_count_hint,
        "psu_length_hint": psu_length_hint,
        "form_factor_hint": form_factor_hint,
        "color_hint": color_hint,
        "warranty_years": warranty_years,
        "caps_hint": caps_hint,
        "has_zero_rpm_hint": has_zero_rpm_hint,
        "limit_hint": limit_hint,
        "is_bundle": is_bundle,
        "is_accessory": is_accessory,
    }
    return sku_hint, extra
