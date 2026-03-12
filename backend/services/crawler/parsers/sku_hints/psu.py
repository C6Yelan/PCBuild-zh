# backend/services/crawler/parsers/sku_hints/psu.py
from __future__ import annotations

import re

from .common import head_before_brackets, normalize_spaces
from .shared_specs import extract_warranty_years as _extract_warranty_years
from .shared_specs import normalize_nonempty_lines as _normalize_lines
from .shared_specs import normalized_title_line
from .shared_specs import strip_leading_bracket_tags as _strip_leading_bracket_tags

_WATT_RE = re.compile(r"(?<![A-Za-z0-9])(\d{2,4})\s*W(?![A-Za-z0-9])", flags=re.IGNORECASE) # 用於抓取瓦數，例如 650W、1200 W 等。
_ATX_VERSION_RE = re.compile(r"ATX\s*3\.(0|1)", flags=re.IGNORECASE) # 用於抓取 ATX 版本，例如 ATX 3.0、ATX3.1 等。
_PCIE_VERSION_RE = re.compile(r"(?<![A-Za-z0-9])PCI-?E\s*5(?:\.(0|1))?(?![A-Za-z0-9])", flags=re.IGNORECASE) # 用於抓取 PCIe 版本，例如 PCIe5、PCI-E 5.0、PCIE5.1 等。

_NATIVE_LINE_RE = re.compile(r"原生") # 用於識別是否有原生 12V 連接器字樣。
_NATIVE_2X6_RE = re.compile(r"12V-?2x6", flags=re.IGNORECASE) # 用於識別 12V-2x6 連接器字樣。
_NATIVE_HPW_RE = re.compile(r"12V\s*HPWR", flags=re.IGNORECASE) # 用於識別 12VHPWR 連接器字樣。
_NATIVE_12P4_RE = re.compile(r"12\s*\+\s*4", flags=re.IGNORECASE) # 用於識別 12+4 連接器字樣。
_NATIVE_COUNT_RE = re.compile(r"(?<!\d)(?:[x*＊]\s*)(\d+)", flags=re.IGNORECASE) # 用於抓取連接器數量，例如 x2、*3、＊4 等。

_PSU_LENGTH_RE = re.compile(r"電源長度\s*[:：]\s*(.+)") # 用於抓取電源長度字樣，例如「電源長度: 140mm」。

_SFX_L_RE = re.compile(r"【?\s*SFX-?L\s*】?", flags=re.IGNORECASE) # 用於識別 SFX-L 形式字樣。
_SFX_RE = re.compile(r"【?\s*SFX\s*】?", flags=re.IGNORECASE) # 用於識別 SFX 形式字樣。
_ATX_FORM_RE = re.compile(r"ATX\s*(規格|電源)", flags=re.IGNORECASE) # 用於識別 ATX 形式字樣。

_WHITE_RE = re.compile(r"白色版|白色|(?<![A-Za-z0-9])白(?!金)") # 用於識別白色字樣。
_BLACK_RE = re.compile(r"黑色|(?<![A-Za-z0-9])黑(?!金)") # 用於識別黑色字樣。

_ZERO_RPM_RE = re.compile(r"智慧停轉|停轉|0\s*RPM", flags=re.IGNORECASE) # 用於識別零轉速字樣。
_CAPS_ALL_RE = re.compile(r"全日系") # 用於識別全日系字樣。
_CAPS_MAIN_RE = re.compile(r"主日系") # 用於識別主日系字樣。

_LIMIT_RE = re.compile(r"(限組裝|限購|限量|客訂)") # 用於識別限量、限購等字樣。
_BUNDLE_RE = re.compile(r"(大全配|套裝|組合|bundle)", flags=re.IGNORECASE) # 用於識別套裝、組合等字樣。
_ACCESSORY_RE = re.compile(r"(延長線|套件|轉接|支架|扣具|配件|模組線|轉接線)") # 用於識別配件、轉接線等字樣。

_EFFICIENCY_RULES: list[tuple[re.Pattern[str], str]] = [ # 用於識別並正規化 80 PLUS 效率等級字樣。
    (re.compile(r"鈦金|Titanium", flags=re.IGNORECASE), "titanium"),
    (re.compile(r"白金|Platinum", flags=re.IGNORECASE), "platinum"),
    (re.compile(r"金牌|Gold", flags=re.IGNORECASE), "gold"),
    (re.compile(r"銀牌|Silver", flags=re.IGNORECASE), "silver"),
    (re.compile(r"銅牌|Bronze", flags=re.IGNORECASE), "bronze"),
    (re.compile(r"80\s*\+", flags=re.IGNORECASE), "standard"),
]

_MODULAR_FULL_RE = re.compile(r"全模組|全模") # 用於識別全模組字樣。
_MODULAR_SEMI_RE = re.compile(r"半模組|半模") # 用於識別半模組字樣。
_MODULAR_NON_RE = re.compile(r"直出壓紋線|直出扁線|直出線") # 用於識別非模組字樣。

_CABLE_FLAT_RE = re.compile(r"直出扁線|直出線\s*/\s*扁平線") # 用於識別扁平直出線字樣。
_CABLE_FIXED_RE = re.compile(r"直出壓紋線|直出線|壓紋線材|壓紋線") # 用於識別直出線字樣。

_SPEC_CLEAN_RE = re.compile( # 用於清理型號中的多餘規格字樣。
    r"ATX\s*3\.[01]|ATX3\.[01]|PCI-?E\s*5(?:\.[01])?|PCIE\s*5(?:\.[01])?"
    r"|80\s*\+?\s*(?:PLUS)?\s*(?:銅牌|銀牌|金牌|白金|鈦金|Bronze|Silver|Gold|Platinum|Titanium)"
    r"|銅牌|銀牌|金牌|白金|鈦金|Bronze|Silver|Gold|Platinum|Titanium"
    r"|\d+\s*年(?:保固|保)?|全日系|主日系|智慧停轉|停轉|0\s*RPM",
    flags=re.IGNORECASE,
)


def _extract_watt(texts: list[str]) -> int | None: # 抓取最大瓦數。
    watts: list[int] = []
    for text in texts:
        watts.extend(int(m.group(1)) for m in _WATT_RE.finditer(text or ""))
    return max(watts) if watts else None


def _extract_efficiency(text: str) -> str | None: # 抓取並正規化 80 PLUS 效率等級字樣。
    for pat, label in _EFFICIENCY_RULES:
        if pat.search(text or ""):
            return label
    return None


def _extract_modular(text: str) -> str | None: # 抓取模組化類型字樣。
    if _MODULAR_NON_RE.search(text or ""):
        return "non"
    if _MODULAR_FULL_RE.search(text or ""):
        return "full"
    if _MODULAR_SEMI_RE.search(text or ""):
        return "semi"
    return None


def _extract_cable_type(text: str) -> str | None: # 抓取線材類型字樣。
    if _CABLE_FLAT_RE.search(text or ""):
        return "flat_fixed"
    if _CABLE_FIXED_RE.search(text or ""):
        return "fixed"
    return None


def _extract_atx_version(texts: list[str]) -> str | None: # 抓取 ATX 版本字樣。
    for text in texts:
        m = _ATX_VERSION_RE.search(text or "")
        if m:
            return f"3.{m.group(1)}"
    return None


def _extract_pcie_version(text: str) -> str | None: # 抓取並正規化 PCIe 版本字樣。
    found = False
    for m in _PCIE_VERSION_RE.finditer(text or ""):
        found = True
        if m.group(1) == "1":
            return "5.1"
    return "5.0" if found else None


def _extract_native_connector(lines: list[str], title: str) -> tuple[str | None, int | None]: # 抓取原生 12V 連接器類型及數量字樣。
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
        counts = [int(m.group(1)) for m in _NATIVE_COUNT_RE.finditer(line)]
        count = max(counts) if counts else None
        return hint, count
    return None, None


def _extract_psu_length(lines: list[str]) -> str | None: # 抓取電源長度字樣。
    for line in lines:
        m = _PSU_LENGTH_RE.search(line)
        if not m:
            continue
        length = normalize_spaces(m.group(1))
        return length or None
    return None


def _extract_form_factor(texts: list[str]) -> str | None: # 抓取電源形式字樣。
    for text in texts:
        if _SFX_L_RE.search(text or ""):
            return "sfx-l"
        if _SFX_RE.search(text or ""):
            return "sfx"
    for text in texts:
        if _ATX_FORM_RE.search(text or ""):
            return "atx"
    return None


def _extract_color(text: str) -> str | None: # 抓取顏色字樣。
    if _WHITE_RE.search(text or ""):
        return "white"
    if _BLACK_RE.search(text or ""):
        return "black"
    return None


def _extract_caps_hint(text: str) -> str | None: # 抓取日系電容字樣。
    if _CAPS_ALL_RE.search(text or ""):
        return "all_japanese"
    if _CAPS_MAIN_RE.search(text or ""):
        return "main_japanese"
    return None


def _clean_model_head(text: str) -> str:  # 清理並正規化型號開頭字樣。
    text = _strip_leading_bracket_tags(text)

    # NEW: 若開頭是「品牌(代理/別名) 型號...」，先移除這個括號，避免 head_before_brackets 只剩品牌
    text = re.sub(r"^([^\s(（【\[]+)[(（][^）)]{1,80}[)）]\s*", r"\1 ", text)

    head = head_before_brackets(text)
    head = re.split(r"[／/|｜]", head, 1)[0]
    head = re.split(r"[，,、:：]", head, 1)[0]
    head = _SPEC_CLEAN_RE.sub(" ", head)
    return normalize_spaces(head)


def extract_psu_sku_hint(title: str) -> str | None: # 抓取 PSU 型號提示字樣。
    line = normalized_title_line(title)
    head = _clean_model_head(line)
    if head:
        return head
    fallback = normalize_spaces(head_before_brackets(_strip_leading_bracket_tags(line)) or line)
    return fallback or None


def extract_psu_hints(title: str, desc_lines: list[str] | None = None) -> tuple[str | None, dict[str, object]]: # 抓取 PSU 型號提示字樣及其他提示字樣。
    line = normalized_title_line(title)
    desc = _normalize_lines(desc_lines)
    texts = [line] + desc

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
    warranty_years = _extract_warranty_years(texts)
    caps_hint = _extract_caps_hint(line)
    has_zero_rpm_hint = True if _ZERO_RPM_RE.search(line) else None

    limit_hint = None
    limit_m = _LIMIT_RE.search(line)
    if limit_m:
        limit_hint = limit_m.group(1)

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
