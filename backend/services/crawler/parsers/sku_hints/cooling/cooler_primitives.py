from __future__ import annotations

import re

from ..shared_specs import extract_brand_hint as shared_extract_brand_hint
from ..shared_specs import extract_limit_hint
from ..shared_specs import extract_model_hint as shared_extract_model_hint
from ..shared_specs import normalize_length_mm

_NOTICE_RE = re.compile(r"(提醒|注意事項|說明)")
_PASTE_RE = re.compile(r"(導熱膏|散熱膏|液態金屬|道康膏|涼膏)")
_PAD_RE = re.compile(r"(導熱墊|導熱片|Thermal\s*Pad)", flags=re.IGNORECASE)
_M2_RE = re.compile(r"M\.2", flags=re.IGNORECASE)
_M2_LEN_RE = re.compile(r"\b(22110|2280|2260|2242|2230)\b")
_HEATSINK_RE = re.compile(r"散熱")
_LIQUID_RE = re.compile(r"(水冷|冷排|AIO|一體式)", flags=re.IGNORECASE)
_NOTEBOOK_RE = re.compile(
    r"(筆電|Notebook|NotePal|ErgoStand|散熱墊|散熱座|Cooling\s*Pad|Laptop\s*Cooler|Stand)",
    flags=re.IGNORECASE,
)
_AIR_RE = re.compile(r"散熱器")

_LIMIT_RE = re.compile(r"(限購|限組裝|限量|客訂)")
_BUNDLE_RE = re.compile(r"(大全配|套裝|組合)")

_TDP_RE = re.compile(
    r"(?<![A-Za-z0-9])TDP[:\s]*([0-9]{2,4})\s*W?(?![A-Za-z0-9])",
    flags=re.IGNORECASE,
)
_HEIGHT_MM_RE = re.compile(r"(?:高|高度)\s*([0-9]+(?:\.[0-9]+)?)\s*mm", flags=re.IGNORECASE)
_HEIGHT_CM_RE = re.compile(r"(?:高|高度)\s*([0-9]+(?:\.[0-9]+)?)\s*(?:cm|公分)", flags=re.IGNORECASE)
_HEIGHT_NUM_RE = re.compile(r"(?:高|高度)\s*([0-9]+(?:\.[0-9]+)?)")
_HEATPIPE_RE = re.compile(r"(\d+)\s*(?:導管|熱管)")
_HEATPIPE_COUNT_RE = re.compile(r"(?P<n>\d{1,2})\s*(?:導管|熱管)")
_FAN_MULT_RE = re.compile(r"(?i)(?:風扇|fan)\s*[*x×]\s*(\d{1,2})")
_FAN_COUNT_RE = re.compile(r"(?<![A-Za-z0-9-])(\d{1,2})\s*風扇")
_NO_FAN_RE = re.compile(r"(無風扇|不含風扇|不附風扇)", flags=re.IGNORECASE)
_MOUNT_KIT_RE = re.compile(r"(扣具|安裝套件|固定架|背板|支架)", flags=re.IGNORECASE)
_FAN_WORD_RE = re.compile(r"(風扇|fan)", flags=re.IGNORECASE)
_PWM_RE = re.compile(r"(?<![A-Za-z0-9])PWM(?![A-Za-z0-9])", flags=re.IGNORECASE)
_RGB_RE = re.compile(r"(?<![A-Za-z0-9])(A-?RGB|ARGB|RGB)(?![A-Za-z0-9])", flags=re.IGNORECASE)
_PAD_THICKNESS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*mm(?:\(|（)?\s*厚", flags=re.IGNORECASE)
_PAD_DIM_RE = re.compile(r"(\d+(?:\.\d+)?)\s*[xX×]\s*(\d+(?:\.\d+)?)\s*mm", flags=re.IGNORECASE)
_THERMAL_COND_RE = re.compile(r"(\d+(?:\.\d+)?)\s*W\s*/\s*m\s*-?\s*K", flags=re.IGNORECASE)
_WEIGHT_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(?:公克|g)\b", flags=re.IGNORECASE)
_ANY_MM_RE = re.compile(r"(\d+(?:\.\d+)?)\s*mm", flags=re.IGNORECASE)

_SOCKET_RE = re.compile(
    r"(?<![A-Za-z0-9])("
    r"LGA\s*1700|LGA\s*1851|LGA\s*1200|LGA\s*115x|LGA\s*115X|LGA\s*2011|"
    r"LGA\s*2066|LGA\s*3647|LGA\s*4677|"
    r"AM4|AM5|TR4|sTRX4|sTR5|SP6|SP5"
    r")(?![A-Za-z0-9])",
    flags=re.IGNORECASE,
)

_MODEL_REMOVE_RE = re.compile(
    r"(散熱器|散熱膏|導熱膏|散熱墊|導熱墊|導熱片|散熱片|散熱座|筆電散熱座|筆電散熱墊|"
    r"M\.2散熱片|M\.2散熱器|SSD散熱片|SSD散熱器|水冷|冷排|一體式)",
    flags=re.IGNORECASE,
)
_MODEL_HEAD_CLEAN_RE = re.compile(
    rf"{_MODEL_REMOVE_RE.pattern}|{_LIMIT_RE.pattern}",
    flags=re.IGNORECASE,
)
_BRAND_IGNORE = {"CPU", "PWM", "RGB", "ARGB", "AIO", "TDP", "M2", "SSD", "HDD"}

_FAN_WORDS = {
    "單扇": 1,
    "雙扇": 2,
    "三扇": 3,
    "四扇": 4,
}

_AIR_HINT_RE = re.compile(r"(塔散|空冷|下吹|風冷|雙塔|單塔)")

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
    (re.compile(r"^darkflash", flags=re.IGNORECASE), "DARKFLASH"),
    (re.compile(r"^montech", flags=re.IGNORECASE), "MONTECH"),
    (re.compile(r"^scythe", flags=re.IGNORECASE), "SCYTHE"),
    (re.compile(r"^cougar", flags=re.IGNORECASE), "COUGAR"),
]


def detect_cooler_kind(text: str) -> str:
    if _NOTICE_RE.search(text or ""):
        return "notice"
    if _PASTE_RE.search(text or ""):
        return "thermal_paste"
    if _NOTEBOOK_RE.search(text or ""):
        return "notebook_cooler"
    if _PAD_RE.search(text or ""):
        return "thermal_pad"
    if (_M2_RE.search(text or "") or _M2_LEN_RE.search(text or "")) and _HEATSINK_RE.search(text or ""):
        return "ssd_heatsink"
    if _LIQUID_RE.search(text or ""):
        return "cpu_liquid_aio"
    if _HEATPIPE_RE.search(text or "") or _AIR_HINT_RE.search(text or "") or _AIR_RE.search(text or ""):
        return "cpu_air"
    return "other"


def extract_cooler_brand_hint(text: str) -> str | None:
    return shared_extract_brand_hint(
        text,
        prefix_rules=_BRAND_PREFIX_RULES,
        ignore_tokens=_BRAND_IGNORE,
    )


def extract_cooler_model_hint(text: str) -> str | None:
    return shared_extract_model_hint(text, clean_pattern=_MODEL_HEAD_CLEAN_RE)


def extract_cooler_limit_hint(texts: list[str]) -> str | None:
    return extract_limit_hint(texts, _LIMIT_RE)


def infer_cooler_bundle(head: str) -> bool:
    return bool(_BUNDLE_RE.search(head))


def infer_cooler_accessory(line: str, cooler_kind_hint: str) -> bool:
    is_mount_kit = True if _MOUNT_KIT_RE.search(line) else False
    if is_mount_kit:
        return True
    return False if cooler_kind_hint in ("cpu_air", "cpu_liquid_aio") else True


def _extract_height_mm(text: str) -> int | None:
    m = _HEIGHT_MM_RE.search(text or "")
    if m:
        return normalize_length_mm(float(m.group(1)), "mm")
    m = _HEIGHT_CM_RE.search(text or "")
    if m:
        return normalize_length_mm(float(m.group(1)), "cm")
    m = _HEIGHT_NUM_RE.search(text or "")
    if m:
        return normalize_length_mm(float(m.group(1)), None, assume_cm_threshold=30)
    return None


def _extract_fan_sizes(text: str) -> list[int] | None:
    t = text or ""
    sizes: set[int] = set()
    for m in re.finditer(r"(?i)(\d{2,3})\s*mm\s*(?:風扇|fan)", t):
        sizes.add(int(m.group(1)))
    for m in re.finditer(r"(?i)(\d{1,2}(?:\.\d+)?)\s*cm\s*(?:風扇|fan)", t):
        sizes.add(int(round(float(m.group(1)) * 10)))
    for m in re.finditer(r"(?i)(?:風扇|fan)\s*[:：]?\s*(\d{2,3})\s*mm", t):
        sizes.add(int(m.group(1)))
    for m in re.finditer(r"(?i)(?:風扇|fan)\s*[:：]?\s*(\d{1,2}(?:\.\d+)?)\s*cm", t):
        sizes.add(int(round(float(m.group(1)) * 10)))
    return sorted(sizes) if sizes else None


def _extract_sockets(text: str) -> list[str] | None:
    sockets: list[str] = []
    seen: set[str] = set()
    for m in _SOCKET_RE.finditer(text or ""):
        raw = m.group(1).replace(" ", "")
        key = raw.upper()
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


def _extract_pad_thickness(text: str) -> float | None:
    m = _PAD_THICKNESS_RE.search(text or "")
    if m:
        return float(m.group(1))
    m = _ANY_MM_RE.search(text or "")
    if m:
        return float(m.group(1))
    return None


def _extract_pad_dimensions(text: str) -> str | None:
    m = _PAD_DIM_RE.search(text or "")
    if not m:
        return None
    return f"{m.group(1)}x{m.group(2)}"


def _extract_thermal_cond(text: str) -> float | None:
    m = _THERMAL_COND_RE.search(text or "")
    return float(m.group(1)) if m else None


def _extract_weight(text: str) -> float | None:
    m = _WEIGHT_RE.search(text or "")
    return float(m.group(1)) if m else None


def extract_cooler_detail_hints(
    *,
    line: str,
    full: str,
    cooler_kind_hint: str,
) -> dict[str, object]:
    details: dict[str, object] = {
        "socket_support_hint": None,
        "tdp_w_hint": None,
        "height_mm_hint": None,
        "heatpipe_count_hint": None,
        "fan_count_hint": None,
        "fan_sizes_mm_hint": None,
        "pwm_hint": None,
        "rgb_hint": None,
        "m2_length_hint": None,
        "pad_thickness_mm_hint": None,
        "pad_dimensions_mm_hint": None,
        "thermal_conductivity_w_mk_hint": None,
        "weight_g_hint": None,
    }

    if cooler_kind_hint == "cpu_air":
        tdp_m = _TDP_RE.search(line)
        if tdp_m:
            details["tdp_w_hint"] = int(tdp_m.group(1))
        details["height_mm_hint"] = _extract_height_mm(line)
        hp_m = _HEATPIPE_COUNT_RE.search(full)
        if hp_m:
            details["heatpipe_count_hint"] = int(hp_m.group("n"))
        for word, count in _FAN_WORDS.items():
            if word in line:
                details["fan_count_hint"] = count
                break
        if details["fan_count_hint"] is None:
            mult_m = _FAN_MULT_RE.search(line)
            if mult_m:
                details["fan_count_hint"] = int(mult_m.group(1))
        if details["fan_count_hint"] is None:
            fan_m = _FAN_COUNT_RE.search(line)
            if fan_m:
                details["fan_count_hint"] = int(fan_m.group(1))
        if details["fan_count_hint"] is None and _FAN_WORD_RE.search(line) and not _NO_FAN_RE.search(line):
            details["fan_count_hint"] = 1
        details["fan_sizes_mm_hint"] = _extract_fan_sizes(line)
        details["pwm_hint"] = True if _PWM_RE.search(full) else None
        details["rgb_hint"] = True if _RGB_RE.search(full) else None
        details["socket_support_hint"] = _extract_sockets(full)
    elif cooler_kind_hint == "cpu_liquid_aio":
        details["pwm_hint"] = True if _PWM_RE.search(full) else None
        details["rgb_hint"] = True if _RGB_RE.search(full) else None
        details["socket_support_hint"] = _extract_sockets(full)
    elif cooler_kind_hint == "notebook_cooler":
        details["rgb_hint"] = True if _RGB_RE.search(full) else None
    elif cooler_kind_hint == "ssd_heatsink":
        m2_m = _M2_LEN_RE.search(full)
        if m2_m:
            details["m2_length_hint"] = int(m2_m.group(1))
        hp_m = _HEATPIPE_COUNT_RE.search(full)
        if hp_m:
            details["heatpipe_count_hint"] = int(hp_m.group("n"))
        details["fan_sizes_mm_hint"] = _extract_fan_sizes(full)
        if _FAN_WORD_RE.search(full) and not _NO_FAN_RE.search(full):
            details["fan_count_hint"] = 1
            mult_m = _FAN_MULT_RE.search(full)
            if mult_m:
                details["fan_count_hint"] = int(mult_m.group(1))
        details["pwm_hint"] = True if _PWM_RE.search(full) else None
        details["rgb_hint"] = True if _RGB_RE.search(full) else None
    elif cooler_kind_hint == "thermal_pad":
        details["pad_thickness_mm_hint"] = _extract_pad_thickness(line)
        details["pad_dimensions_mm_hint"] = _extract_pad_dimensions(line)
        details["thermal_conductivity_w_mk_hint"] = _extract_thermal_cond(line)
    elif cooler_kind_hint == "thermal_paste":
        details["thermal_conductivity_w_mk_hint"] = _extract_thermal_cond(line)
        details["weight_g_hint"] = _extract_weight(line)

    return details


__all__ = [
    "detect_cooler_kind",
    "extract_cooler_brand_hint",
    "extract_cooler_detail_hints",
    "extract_cooler_limit_hint",
    "extract_cooler_model_hint",
    "infer_cooler_accessory",
    "infer_cooler_bundle",
]
