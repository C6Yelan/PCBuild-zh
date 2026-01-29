# backend/services/crawler/parsers/sku_hints/cooler.py
from __future__ import annotations

import re

from .common import first_line, head_before_brackets, normalize_spaces, strip_leading_note

_NOTICE_RE = re.compile(r"(提醒|注意事項|說明)") # 用於識別注意事項類型
_PASTE_RE = re.compile(r"(導熱膏|散熱膏|液態金屬|道康膏|涼膏)") # 用於識別導熱膏類型
_PAD_RE = re.compile(r"(導熱墊|導熱片|Thermal\s*Pad)", flags=re.IGNORECASE) # 用於識別散熱墊類型
_M2_RE = re.compile(r"M\.2", flags=re.IGNORECASE) # 用於識別 M.2 散熱片
_M2_LEN_RE = re.compile(r"\b(22110|2280|2260|2242|2230)\b") # 用於識別 M.2 長度規格
_HEATSINK_RE = re.compile(r"散熱") # 用於識別散熱相關字樣
_LIQUID_RE = re.compile(r"(水冷|冷排|AIO|一體式)", flags=re.IGNORECASE) # 用於識別水冷類型
_NOTEBOOK_RE = re.compile(r"(筆電|Notebook|NotePal|ErgoStand|散熱墊|散熱座|Cooling\s*Pad|Laptop\s*Cooler|Stand)", flags=re.IGNORECASE) # 用於識別筆電散熱座類型
_AIR_RE = re.compile(r"散熱器") # 用於識別空冷散熱器類型

_LIMIT_RE = re.compile(r"(限購|限組裝|限量|客訂)") # 用於識別限購或限組裝
_BUNDLE_RE = re.compile(r"(大全配|套裝|組合)") # 用於識別套裝組合
_PLUS_RE = re.compile(r"[+＋]") # 用於在 '+' 號處切割字串

_TDP_RE = re.compile(r"(?<![A-Za-z0-9])TDP[:\s]*([0-9]{2,4})\s*W?(?![A-Za-z0-9])", flags=re.IGNORECASE) # 提取 TDP 數值
_HEIGHT_MM_RE = re.compile(r"(?:高|高度)\s*([0-9]+(?:\.[0-9]+)?)\s*mm", flags=re.IGNORECASE) # 提取高度（mm）
_HEIGHT_CM_RE = re.compile(r"(?:高|高度)\s*([0-9]+(?:\.[0-9]+)?)\s*(?:cm|公分)", flags=re.IGNORECASE) # 提取高度（cm）
_HEIGHT_NUM_RE = re.compile(r"(?:高|高度)\s*([0-9]+(?:\.[0-9]+)?)") # 提取高度（無單位）
_HEATPIPE_RE = re.compile(r"(\d+)\s*(?:導管|熱管)") # 提取熱導管數量
_HEATPIPE_COUNT_RE = re.compile(r"(?P<n>\d{1,2})\s*(?:導管|熱管)")
_FAN_MULT_RE = re.compile(r"(?i)(?:風扇|fan)\s*[*x×]\s*(\d{1,2})")  # 風扇*2 / fan x2
# 避免 TL-E12風扇、A12X25風扇 這種「型號尾碼」誤判成數量
_FAN_COUNT_RE = re.compile(r"(?<![A-Za-z0-9-])(\d{1,2})\s*風扇")
_NO_FAN_RE = re.compile(r"(無風扇|不含風扇|不附風扇)", flags=re.IGNORECASE)
_MOUNT_KIT_RE = re.compile(r"(扣具|安裝套件|固定架|背板|支架)", flags=re.IGNORECASE)
_FAN_MM_RE = re.compile(r"(\d{2,3})\s*mm", flags=re.IGNORECASE) # 提取風扇尺寸（mm）
_FAN_CM_RE = re.compile(r"(\d+(?:\.\d+)?)\s*cm", flags=re.IGNORECASE) # 提取風扇尺寸（cm）
_FAN_WORD_RE = re.compile(r"(風扇|fan)", flags=re.IGNORECASE) # 用於識別風扇相關字樣
_PWM_RE = re.compile(r"(?<![A-Za-z0-9])PWM(?![A-Za-z0-9])", flags=re.IGNORECASE) # 用於識別 PWM 控制
_RGB_RE = re.compile(r"(?<![A-Za-z0-9])(A-?RGB|ARGB|RGB)(?![A-Za-z0-9])", flags=re.IGNORECASE) # 用於識別 RGB 燈效
_PAD_THICKNESS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*mm(?:\(|（)?\s*厚", flags=re.IGNORECASE) # 提取散熱墊厚度（mm）
_PAD_DIM_RE = re.compile(r"(\d+(?:\.\d+)?)\s*[xX×]\s*(\d+(?:\.\d+)?)\s*mm", flags=re.IGNORECASE) # 提取散熱墊尺寸（mm）
_THERMAL_COND_RE = re.compile(r"(\d+(?:\.\d+)?)\s*W\s*/\s*m\s*-?\s*K", flags=re.IGNORECASE) # 提取導熱係數（W/m-K）
_WEIGHT_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(?:公克|g)\b", flags=re.IGNORECASE) # 提取重量（公克）
_ANY_MM_RE = re.compile(r"(\d+(?:\.\d+)?)\s*mm", flags=re.IGNORECASE) # 提取任意毫米數值

_WARRANTY_RE = re.compile(r"(\d+)\s*年(?:保)?") # 提取保固年限（數字）
_WARRANTY_CN = { # 提取保固年限（中文）
    "一年": 1,
    "二年": 2,
    "三年": 3,
    "五年": 5,
}

_SOCKET_RE = re.compile( # 提取支援插槽
    r"(?<![A-Za-z0-9])("
    r"LGA\s*1700|LGA\s*1851|LGA\s*1200|LGA\s*115x|LGA\s*115X|LGA\s*2011|"
    r"LGA\s*2066|LGA\s*3647|LGA\s*4677|"
    r"AM4|AM5|TR4|sTRX4|sTR5|SP6|SP5"
    r")(?![A-Za-z0-9])",
    flags=re.IGNORECASE,
)

_MODEL_REMOVE_RE = re.compile( # 用於清除非型號的規格字串
    r"(散熱器|散熱膏|導熱膏|散熱墊|導熱墊|導熱片|散熱片|散熱座|筆電散熱座|筆電散熱墊|"
    r"M\.2散熱片|M\.2散熱器|SSD散熱片|SSD散熱器|水冷|冷排|一體式)",
    flags=re.IGNORECASE,
)
_BRAND_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{1,}") # 提取可能的品牌字串
_BRAND_IGNORE = {"CPU", "PWM", "RGB", "ARGB", "AIO", "TDP", "M2", "SSD", "HDD"} # 忽略的品牌字串

_FAN_WORDS = { # 用於識別風扇尺寸附近的字樣
    "單扇": 1,
    "雙扇": 2,
    "三扇": 3,
    "四扇": 4,
}

_AIR_HINT_RE = re.compile(r"(塔散|空冷|下吹|風冷|雙塔|單塔)") # 用於識別空冷散熱相關字樣

_BRAND_PREFIX_RULES: list[tuple[re.Pattern[str], str]] = [ # 品牌前綴規則
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
    (re.compile(r"^darkflash", flags=re.IGNORECASE), "DARKFLASH"),
    (re.compile(r"^montech", flags=re.IGNORECASE), "MONTECH"),
    (re.compile(r"^scythe", flags=re.IGNORECASE), "SCYTHE"),
    (re.compile(r"^cougar", flags=re.IGNORECASE), "COUGAR"),
]


def _detect_cooler_kind(text: str) -> str: # 偵測散熱器類型。
    if _NOTICE_RE.search(text or ""):
        return "notice" # 注意事項
    if _PASTE_RE.search(text or ""):
        return "thermal_paste" # 導熱膏
    if _NOTEBOOK_RE.search(text or ""):
        return "notebook_cooler" # 筆電散熱座
    if _PAD_RE.search(text or ""):
        return "thermal_pad" # 導熱墊
    if (_M2_RE.search(text or "") or _M2_LEN_RE.search(text or "")) and _HEATSINK_RE.search(text or ""):
        return "ssd_heatsink" # M.2 散熱片
    if _LIQUID_RE.search(text or ""):
        return "cpu_liquid_aio" # 水冷一體式
    if _HEATPIPE_RE.search(text or ""):
        return "cpu_air" # 空冷散熱器(塔扇)
    if _AIR_HINT_RE.search(text or ""):
        return "cpu_air" # 空冷散熱器(塔扇)
    if _AIR_RE.search(text or ""):
        return "cpu_air" # 空冷散熱器(塔扇)
    return "other"


def _extract_brand(text: str) -> str | None: # 提取品牌提示。
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


def _extract_model_hint(text: str) -> str | None: # 提取型號提示。
    head = head_before_brackets(text)
    head = re.split(r"[／/|｜]", head, 1)[0]
    head = re.split(r"[，,、:：]", head, 1)[0]
    head = _MODEL_REMOVE_RE.sub(" ", head)
    head = _LIMIT_RE.sub(" ", head)
    head = normalize_spaces(head)
    return head or None


def _extract_height_mm(text: str) -> int | None: # 提取高度（mm）。
    m = _HEIGHT_MM_RE.search(text or "")
    if m:
        return int(round(float(m.group(1))))
    m = _HEIGHT_CM_RE.search(text or "")
    if m:
        return int(round(float(m.group(1)) * 10))
    m = _HEIGHT_NUM_RE.search(text or "")
    if m:
        val = float(m.group(1))
        if val <= 30:
            return int(round(val * 10))
    return None


def _extract_fan_sizes(text: str) -> list[int] | None:
    """
    只在「風扇」的近距離語境下抓尺寸，避免像「雙風扇/高15cm」把高度 15cm 誤當風扇尺寸。
    支援：
      - 12cm風扇 / 120mm風扇
      - 風扇12cm / 風扇120mm
    """
    t = text or ""
    sizes: set[int] = set()
    # number + unit + fan
    for m in re.finditer(r"(?i)(\d{2,3})\s*mm\s*(?:風扇|fan)", t):
        sizes.add(int(m.group(1)))
    for m in re.finditer(r"(?i)(\d{1,2}(?:\.\d+)?)\s*cm\s*(?:風扇|fan)", t):
        sizes.add(int(round(float(m.group(1)) * 10)))
    # fan + number + unit
    for m in re.finditer(r"(?i)(?:風扇|fan)\s*[:：]?\s*(\d{2,3})\s*mm", t):
        sizes.add(int(m.group(1)))
    for m in re.finditer(r"(?i)(?:風扇|fan)\s*[:：]?\s*(\d{1,2}(?:\.\d+)?)\s*cm", t):
        sizes.add(int(round(float(m.group(1)) * 10)))
    return sorted(sizes) if sizes else None


def _extract_sockets(text: str) -> list[str] | None: # 提取支援插槽。
    sockets: list[str] = []
    seen: set[str] = set()
    for m in _SOCKET_RE.finditer(text or ""):
        raw = m.group(1).replace(" ", "")
        key = raw.upper()
        norm = raw
        if key in ("STRX4",):
            norm = "sTRX4"
        elif key in ("STR5",):
            norm = "sTR5"
        elif key == "LGA115X":
            norm = "LGA115x"
        else:
            norm = key
        if norm not in seen:
            seen.add(norm)
            sockets.append(norm)
    return sockets or None


def _extract_pad_thickness(text: str) -> float | None: # 提取散熱墊厚度（mm）。
    m = _PAD_THICKNESS_RE.search(text or "")
    if m:
        return float(m.group(1))
    m = _ANY_MM_RE.search(text or "")
    if m:
        return float(m.group(1))
    return None


def _extract_pad_dimensions(text: str) -> str | None: # 提取散熱墊尺寸（mm）。
    m = _PAD_DIM_RE.search(text or "")
    if not m:
        return None
    a = m.group(1)
    b = m.group(2)
    return f"{a}x{b}"


def _extract_thermal_cond(text: str) -> float | None: # 提取導熱係數（W/m-K）。
    m = _THERMAL_COND_RE.search(text or "")
    return float(m.group(1)) if m else None


def _extract_weight(text: str) -> float | None: # 提取重量（公克）。
    m = _WEIGHT_RE.search(text or "")
    return float(m.group(1)) if m else None


def _extract_warranty_years(text: str) -> int | None: #　提取保固年限。
    m = _WARRANTY_RE.search(text or "")
    if m:
        return int(m.group(1))
    for key, val in _WARRANTY_CN.items():
        if key in (text or ""):
            return val
    return None


def extract_cooler_sku_hint(title: str) -> str | None: # 回傳散熱器型號提示（sku_hint）。
    line = normalize_spaces(strip_leading_note(first_line(title)))
    return _extract_model_hint(line)


def extract_cooler_hints(title: str) -> tuple[str | None, dict[str, object]]:
    """
    回傳 (sku_hint, extra)；extra keys 固定且必須存在：
    brand_hint, model_hint, cooler_kind_hint, socket_support_hint, tdp_w_hint,
    height_mm_hint, heatpipe_count_hint, fan_count_hint, fan_sizes_mm_hint,
    pwm_hint, rgb_hint, m2_length_hint, pad_thickness_mm_hint,
    pad_dimensions_mm_hint, thermal_conductivity_w_mk_hint, weight_g_hint,
    warranty_years, limit_hint, is_bundle, is_accessory
    """
    raw = strip_leading_note(title)
    line = normalize_spaces(first_line(raw))          # 用於 model/sku 等「第一行語意」
    full = normalize_spaces(raw)                      # 用於掃 PWM/RGB/socket 這類「可能在第二行」的資訊
    head = head_before_brackets(line)

    cooler_kind_hint = _detect_cooler_kind(line)
    is_mount_kit = True if _MOUNT_KIT_RE.search(line) else False
    is_accessory = True if is_mount_kit else (False if cooler_kind_hint in ("cpu_air", "cpu_liquid_aio") else True)
    is_bundle = bool(_BUNDLE_RE.search(head))

    limit_hint = None
    limit_m = _LIMIT_RE.search(full)
    if limit_m:
        limit_hint = limit_m.group(1)

    brand_hint = _extract_brand(head or line)
    model_hint = _extract_model_hint(line)
    sku_hint = model_hint

    socket_support_hint = None
    tdp_w_hint = None
    height_mm_hint = None
    heatpipe_count_hint = None
    fan_count_hint = None
    fan_sizes_mm_hint = None
    pwm_hint = None
    rgb_hint = None
    m2_length_hint = None
    pad_thickness_mm_hint = None
    pad_dimensions_mm_hint = None
    thermal_conductivity_w_mk_hint = None
    weight_g_hint = None

    if cooler_kind_hint == "cpu_air":
        tdp_m = _TDP_RE.search(line)
        if tdp_m:
            tdp_w_hint = int(tdp_m.group(1))
        height_mm_hint = _extract_height_mm(line)
        hp_m = _HEATPIPE_COUNT_RE.search(full)
        if hp_m:
            heatpipe_count_hint = int(hp_m.group("n"))
        for word, count in _FAN_WORDS.items():
            if word in line:
                fan_count_hint = count
                break
        if fan_count_hint is None:
            mult_m = _FAN_MULT_RE.search(line)  # 風扇*2
            if mult_m:
                fan_count_hint = int(mult_m.group(1))
        if fan_count_hint is None:
            fan_m = _FAN_COUNT_RE.search(line)  # 2風扇
            if fan_m:
                fan_count_hint = int(fan_m.group(1))
        if fan_count_hint is None and _FAN_WORD_RE.search(line) and not _NO_FAN_RE.search(line):
            fan_count_hint = 1  # 有提到「風扇」但沒講數量，保守推 1
        fan_sizes_mm_hint = _extract_fan_sizes(line)
        pwm_hint = True if _PWM_RE.search(full) else None
        rgb_hint = True if _RGB_RE.search(full) else None
        socket_support_hint = _extract_sockets(full)
    elif cooler_kind_hint == "cpu_liquid_aio":
        # AIO 常把 PWM/RGB/支援腳位寫在第二行，至少補齊這三個
        pwm_hint = True if _PWM_RE.search(full) else None
        rgb_hint = True if _RGB_RE.search(full) else None
        socket_support_hint = _extract_sockets(full)
    elif cooler_kind_hint == "notebook_cooler":
        rgb_hint = True if _RGB_RE.search(line) else None
    elif cooler_kind_hint in ("ssd_heatsink", "notebook_cooler"):
        # 這兩類常見 PWM/RGB（例如帶小風扇的 SSD 散熱、RGB 筆電散熱座）
        pwm_hint = True if _PWM_RE.search(full) else None
        rgb_hint = True if _RGB_RE.search(full) else None
    elif cooler_kind_hint == "ssd_heatsink":
        m2_m = _M2_LEN_RE.search(line)
        if m2_m:
            m2_length_hint = int(m2_m.group(1))
        hp_m = _HEATPIPE_RE.search(line)
        if hp_m:
            heatpipe_count_hint = int(hp_m.group(1))
        fan_sizes_mm_hint = _extract_fan_sizes(line)
        if _FAN_WORD_RE.search(line) and not _NO_FAN_RE.search(line):
            fan_count_hint = 1
            mult_m = _FAN_MULT_RE.search(line)
            if mult_m:
                fan_count_hint = int(mult_m.group(1))
        pwm_hint = True if _PWM_RE.search(line) else None
    elif cooler_kind_hint == "thermal_pad":
        pad_thickness_mm_hint = _extract_pad_thickness(line)
        pad_dimensions_mm_hint = _extract_pad_dimensions(line)
        thermal_conductivity_w_mk_hint = _extract_thermal_cond(line)
    elif cooler_kind_hint == "thermal_paste":
        thermal_conductivity_w_mk_hint = _extract_thermal_cond(line)
        weight_g_hint = _extract_weight(line)

    warranty_years = _extract_warranty_years(full)

    extra = {
        "brand_hint": brand_hint,
        "model_hint": model_hint,
        "cooler_kind_hint": cooler_kind_hint,
        "socket_support_hint": socket_support_hint,
        "tdp_w_hint": tdp_w_hint,
        "height_mm_hint": height_mm_hint,
        "heatpipe_count_hint": heatpipe_count_hint,
        "fan_count_hint": fan_count_hint,
        "fan_sizes_mm_hint": fan_sizes_mm_hint,
        "pwm_hint": pwm_hint,
        "rgb_hint": rgb_hint,
        "m2_length_hint": m2_length_hint,
        "pad_thickness_mm_hint": pad_thickness_mm_hint,
        "pad_dimensions_mm_hint": pad_dimensions_mm_hint,
        "thermal_conductivity_w_mk_hint": thermal_conductivity_w_mk_hint,
        "weight_g_hint": weight_g_hint,
        "warranty_years": warranty_years,
        "limit_hint": limit_hint,
        "is_bundle": is_bundle,
        "is_accessory": is_accessory,
    }
    return sku_hint, extra
