from __future__ import annotations

import re

from ..shared_specs import normalize_length_mm

_TDP_RE = re.compile(
    r"(?<![A-Za-z0-9])TDP[:\s]*([0-9]{2,4})\s*W?(?![A-Za-z0-9])",
    flags=re.IGNORECASE,
)
_HEIGHT_MM_RE = re.compile(r"(?:高|高度)\s*([0-9]+(?:\.[0-9]+)?)\s*mm", flags=re.IGNORECASE)
_HEIGHT_CM_RE = re.compile(r"(?:高|高度)\s*([0-9]+(?:\.[0-9]+)?)\s*(?:cm|公分)", flags=re.IGNORECASE)
_HEIGHT_NUM_RE = re.compile(r"(?:高|高度)\s*([0-9]+(?:\.[0-9]+)?)")
_HEATPIPE_COUNT_RE = re.compile(r"(?P<n>\d{1,2})\s*(?:導管|熱管)")
_FAN_MULT_RE = re.compile(r"(?i)(?:風扇|fan)\s*[*x×]\s*(\d{1,2})")
_FAN_COUNT_RE = re.compile(r"(?<![A-Za-z0-9-])(\d{1,2})\s*風扇")
_NO_FAN_RE = re.compile(r"(無風扇|不含風扇|不附風扇)", flags=re.IGNORECASE)
_FAN_WORD_RE = re.compile(r"(風扇|fan)", flags=re.IGNORECASE)
_PWM_RE = re.compile(r"(?<![A-Za-z0-9])PWM(?![A-Za-z0-9])", flags=re.IGNORECASE)
_RGB_RE = re.compile(r"(?<![A-Za-z0-9])(A-?RGB|ARGB|RGB)(?![A-Za-z0-9])", flags=re.IGNORECASE)
_PAD_THICKNESS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*mm(?:\(|（)?\s*厚", flags=re.IGNORECASE)
_PAD_DIM_RE = re.compile(r"(\d+(?:\.\d+)?)\s*[xX×]\s*(\d+(?:\.\d+)?)\s*mm", flags=re.IGNORECASE)
_THERMAL_COND_RE = re.compile(r"(\d+(?:\.\d+)?)\s*W\s*/\s*m\s*-?\s*K", flags=re.IGNORECASE)
_WEIGHT_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(?:公克|g)\b", flags=re.IGNORECASE)
_ANY_MM_RE = re.compile(r"(\d+(?:\.\d+)?)\s*mm", flags=re.IGNORECASE)
_M2_LEN_RE = re.compile(r"\b(22110|2280|2260|2242|2230)\b")
_SOCKET_RE = re.compile(
    r"(?<![A-Za-z0-9])("
    r"LGA\s*1700|LGA\s*1851|LGA\s*1200|LGA\s*115x|LGA\s*115X|LGA\s*2011|"
    r"LGA\s*2066|LGA\s*3647|LGA\s*4677|"
    r"AM4|AM5|TR4|sTRX4|sTR5|SP6|SP5"
    r")(?![A-Za-z0-9])",
    flags=re.IGNORECASE,
)

_FAN_WORDS = {
    "單扇": 1,
    "雙扇": 2,
    "三扇": 3,
    "四扇": 4,
}


def extract_cooler_height_mm(text: str) -> int | None:
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


def extract_cooler_fan_sizes(text: str) -> list[int] | None:
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


def extract_cooler_sockets(text: str) -> list[str] | None:
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


def extract_cooler_pad_thickness(text: str) -> float | None:
    m = _PAD_THICKNESS_RE.search(text or "")
    if m:
        return float(m.group(1))
    m = _ANY_MM_RE.search(text or "")
    if m:
        return float(m.group(1))
    return None


def extract_cooler_pad_dimensions(text: str) -> str | None:
    m = _PAD_DIM_RE.search(text or "")
    if not m:
        return None
    return f"{m.group(1)}x{m.group(2)}"


def extract_cooler_thermal_conductivity(text: str) -> float | None:
    m = _THERMAL_COND_RE.search(text or "")
    return float(m.group(1)) if m else None


def extract_cooler_weight(text: str) -> float | None:
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
        details["height_mm_hint"] = extract_cooler_height_mm(line)
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
        details["fan_sizes_mm_hint"] = extract_cooler_fan_sizes(line)
        details["pwm_hint"] = True if _PWM_RE.search(full) else None
        details["rgb_hint"] = True if _RGB_RE.search(full) else None
        details["socket_support_hint"] = extract_cooler_sockets(full)
    elif cooler_kind_hint == "cpu_liquid_aio":
        details["pwm_hint"] = True if _PWM_RE.search(full) else None
        details["rgb_hint"] = True if _RGB_RE.search(full) else None
        details["socket_support_hint"] = extract_cooler_sockets(full)
    elif cooler_kind_hint == "notebook_cooler":
        details["rgb_hint"] = True if _RGB_RE.search(full) else None
    elif cooler_kind_hint == "ssd_heatsink":
        m2_m = _M2_LEN_RE.search(full)
        if m2_m:
            details["m2_length_hint"] = int(m2_m.group(1))
        hp_m = _HEATPIPE_COUNT_RE.search(full)
        if hp_m:
            details["heatpipe_count_hint"] = int(hp_m.group("n"))
        details["fan_sizes_mm_hint"] = extract_cooler_fan_sizes(full)
        if _FAN_WORD_RE.search(full) and not _NO_FAN_RE.search(full):
            details["fan_count_hint"] = 1
            mult_m = _FAN_MULT_RE.search(full)
            if mult_m:
                details["fan_count_hint"] = int(mult_m.group(1))
        details["pwm_hint"] = True if _PWM_RE.search(full) else None
        details["rgb_hint"] = True if _RGB_RE.search(full) else None
    elif cooler_kind_hint == "thermal_pad":
        details["pad_thickness_mm_hint"] = extract_cooler_pad_thickness(line)
        details["pad_dimensions_mm_hint"] = extract_cooler_pad_dimensions(line)
        details["thermal_conductivity_w_mk_hint"] = extract_cooler_thermal_conductivity(line)
    elif cooler_kind_hint == "thermal_paste":
        details["thermal_conductivity_w_mk_hint"] = extract_cooler_thermal_conductivity(line)
        details["weight_g_hint"] = extract_cooler_weight(line)

    return details
