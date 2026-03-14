# backend/services/crawler/parsers/sku_hints/liquid_cooling.py
from __future__ import annotations

import re

from ..common import head_before_brackets, normalize_spaces, strip_leading_note
from ..shared_specs import extract_model_head
from ..shared_specs import normalized_title_line

_RADIATOR_SIZE_RE = re.compile(r"(?<!\d)(120|240|280|360|420)(?!\d)") # 水冷排尺寸（mm）
_THICKNESS_MM_RE = re.compile(r"(?<!\d)(\d{2,3})\s*mm(?![A-Za-z0-9])", flags=re.IGNORECASE) # 水冷排厚度（mm）
_THICKNESS_HINT_RE = re.compile(r"(厚排|厚冷排|加厚|厚[:：]?|厚)") # 用來排除風扇厚度誤判的提示詞
_THICKNESS_CM_RE = re.compile(r"厚[:：]\s*(\d+(?:\.\d+)?)\s*(?:cm)?", flags=re.IGNORECASE) # 水冷排厚度（cm）
_FAN_RE = re.compile(r"(風扇|fan)", flags=re.IGNORECASE) # 用來排除風扇厚度誤判的詞彙
_LCD_RE = re.compile(r"(?<!\d)(\d+(?:\.\d+)?)\s*(?:吋|\")") # LCD 尺寸（吋）

_ARGB_RE = re.compile(r"(?<![A-Za-z0-9])(A-?RGB|A\.RGB|ARGB|5V\s*3PIN)(?![A-Za-z0-9])", flags=re.IGNORECASE) # ARGB 提示
_RGB_RE = re.compile(r"(?<![A-Za-z0-9])RGB(?![A-Za-z0-9])", flags=re.IGNORECASE) # RGB 提示

_LIMIT_RE = re.compile(r"(限組裝|限購|限量)") # 限制提示詞
_BUNDLE_RE = re.compile(r"(大全配|套裝|組合|bundle)", flags=re.IGNORECASE) # 套裝提示詞
_PLUS_RE = re.compile(r"[+＋]") # 加號
_ACCESSORY_RE = re.compile(r"(扣具|支架|轉接|控制器|延長線|套件|配件|管路|水冷液|水冷頭風扇)") # 配件提示詞
_ACCESSORY_NEG_RE = re.compile(r"(不含|未含|無含|不附|未附|無附)\s*控制器")  # 避免「不含控制器」誤判為配件

# 保固年份：同時支援「5年保/5年保固」與「6年【WXZ】/6年【XZ】」這種寫法
_WARRANTY_RE = re.compile(r"(\d{1,2})\s*年(?:(?:保固|保)\b|(?=[【\[]))")
_REGISTER_RE = re.compile(r"註冊\s*(\d+)\s*\+\s*(\d+)\s*年?")  # 登錄延長保固（必須有「註冊」才算）

_BRAND_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{1,}") # 品牌可能的字元組合
_BRAND_IGNORE = {"CPU", "PWM", "RGB", "ARGB", "AIO", "TDP", "M2", "SSD", "HDD", "LCD"} # 忽略的品牌字串

_DRGB_RE = re.compile(r"(?<![A-Za-z0-9])D-?RGB(?![A-Za-z0-9])", flags=re.IGNORECASE) # 排除 D-RGB 誤判

_BRAND_PREFIX_RULES: list[tuple[re.Pattern[str], str]] = [ # 品牌前綴對應規則
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

_SOCKET_RULES: list[tuple[re.Pattern[str], str]] = [ # 支援插槽對應規則
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


def _extract_brand(text: str) -> str | None: # 從標題中抽出品牌提示。
    head = (text or "").strip()
    for pat, norm in _BRAND_PREFIX_RULES:
        if pat.search(head):
            return norm
    for m in _BRAND_TOKEN_RE.finditer(text or ""):
        token = m.group(0).upper()
        if token in _BRAND_IGNORE:
            continue
        return token
    return None


def _extract_model_hint(text: str) -> str | None: # 從標題中抽出型號提示。
    head = extract_model_head(text)
    head = normalize_spaces(head)
    return head or None


def _extract_radiator_size(text: str) -> int | None: # 從標題中抽出水冷排尺寸提示（mm）。
    m = _RADIATOR_SIZE_RE.search(text or "")
    return int(m.group(1)) if m else None


def _extract_radiator_thickness(text: str) -> int | None: # 從標題中抽出水冷排厚度提示（mm）。
    m = _THICKNESS_CM_RE.search(text or "")
    if m:
        return int(round(float(m.group(1)) * 10))
    for m in _THICKNESS_MM_RE.finditer(text or ""):
        tail = (text or "")[m.end():m.end() + 3]
        if _FAN_RE.search(tail):
            continue
        window = (text or "")[max(0, m.start() - 8):min(len(text or ""), m.end() + 8)]
        if _THICKNESS_HINT_RE.search(window):
            return int(m.group(1))
    return None


def _extract_lcd_size(text: str) -> float | None: # 從標題中抽出 LCD 尺寸提示（吋）。
    m = _LCD_RE.search(text or "")
    if not m:
        return None
    size = float(m.group(1))
    # 6.5/6.67/6.86 吋等大螢幕 AIO 也要保留
    return size


def _extract_rgb_hint(text: str) -> str | None: # 從標題中抽出 RGB/ARGB 提示。
    if _DRGB_RE.search(text or ""):
        return "d-rgb"
    if _ARGB_RE.search(text or ""):
        return "argb"
    if _RGB_RE.search(text or ""):
        return "rgb"
    return None


def _extract_sockets(text: str) -> list[str] | None: # 從標題中抽出支援插槽提示。
    found: set[str] = set()
    for pat, norm in _SOCKET_RULES:
        if pat.search(text or ""):
            found.add(norm)
    if not found:
        return None
    return sorted(found)


def _extract_warranty_years(text: str) -> int | None: # 從標題中抽出保固年限提示。
    candidates: list[int] = []
    for m in _WARRANTY_RE.finditer(text or ""):
        candidates.append(int(m.group(1)))
    for m in _REGISTER_RE.finditer(text or ""):
        candidates.append(int(m.group(1)) + int(m.group(2)))
    return max(candidates) if candidates else None

# examples:
# - "…28mm風扇/厚:5.5…" -> radiator_thickness_mm_hint=55
# - "…厚排 45mm…" -> radiator_thickness_mm_hint=45
# - "…360mm…" -> radiator_thickness_mm_hint=None


def extract_liquid_cooling_sku_hint(title: str) -> str | None: # 只回傳 sku_hint(型號提示)，不回傳 extra。
    line = normalized_title_line(title)
    return _extract_model_hint(line)


def extract_liquid_cooling_hints(title: str) -> tuple[str | None, dict[str, object]]:
    """
    回傳 (sku_hint, extra)；extra keys 固定且必須存在：
    brand_hint, model_hint, radiator_size_mm_hint, radiator_thickness_mm_hint,
    lcd_size_inch_hint, rgb_hint, socket_support_hint, warranty_years,
    limit_hint, is_bundle, is_accessory
    """
    # 第一行：用於型號/品牌（避免第二行規格污染 model_hint）
    line1 = normalized_title_line(title)
    head = head_before_brackets(line1)
    # 全標題：用於抓第二行的厚度/ARGB/保固等資訊（把換行當空白）
    full = normalize_spaces(strip_leading_note((title or "").replace("\n", " ")))

    brand_hint = _extract_brand(head or line1)
    model_hint = _extract_model_hint(line1)
    sku_hint = model_hint

    # 這些欄位允許出現在第二行，因此改用 full
    radiator_size_mm_hint = _extract_radiator_size(full)
    radiator_thickness_mm_hint = _extract_radiator_thickness(full)
    lcd_size_inch_hint = _extract_lcd_size(full)
    rgb_hint = _extract_rgb_hint(full)
    socket_support_hint = _extract_sockets(full)
    warranty_years = _extract_warranty_years(full)

    limit_hint = None
    limit_m = _LIMIT_RE.search(full)
    if limit_m:
        limit_hint = limit_m.group(1)

    # bundle/accessory 也用 full，並避免「不含控制器」造成 AIO 誤判
    is_bundle = bool(_BUNDLE_RE.search(full))
    accessory_hit = bool(_ACCESSORY_RE.search(full)) and not bool(_ACCESSORY_NEG_RE.search(full))
    # 避免一般 AIO 因為提到控制器就被誤標：有冷排尺寸的，優先視為 AIO 非配件
    is_accessory = bool(accessory_hit and radiator_size_mm_hint is None)

    extra = {
        "brand_hint": brand_hint,
        "model_hint": model_hint,
        "radiator_size_mm_hint": radiator_size_mm_hint,
        "radiator_thickness_mm_hint": radiator_thickness_mm_hint,
        "lcd_size_inch_hint": lcd_size_inch_hint,
        "rgb_hint": rgb_hint,
        "socket_support_hint": socket_support_hint,
        "warranty_years": warranty_years,
        "limit_hint": limit_hint,
        "is_bundle": is_bundle,
        "is_accessory": is_accessory,
    }
    return sku_hint, extra
