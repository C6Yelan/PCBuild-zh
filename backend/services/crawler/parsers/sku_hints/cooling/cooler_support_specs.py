from __future__ import annotations

import re

from ..shared_specs import normalize_length_mm

TDP_RE = re.compile(
    r"(?<![A-Za-z0-9])TDP[:\s]*([0-9]{2,4})\s*W?(?![A-Za-z0-9])",
    flags=re.IGNORECASE,
)
HEIGHT_MM_RE = re.compile(r"(?:高|高度)\s*([0-9]+(?:\.[0-9]+)?)\s*mm", flags=re.IGNORECASE)
HEIGHT_CM_RE = re.compile(r"(?:高|高度)\s*([0-9]+(?:\.[0-9]+)?)\s*(?:cm|公分)", flags=re.IGNORECASE)
HEIGHT_NUM_RE = re.compile(r"(?:高|高度)\s*([0-9]+(?:\.[0-9]+)?)")
HEATPIPE_COUNT_RE = re.compile(r"(?P<n>\d{1,2})\s*(?:導管|熱管)")
FAN_MULT_RE = re.compile(r"(?i)(?:風扇|fan)\s*[*x×]\s*(\d{1,2})")
FAN_COUNT_RE = re.compile(r"(?<![A-Za-z0-9-])(\d{1,2})\s*風扇")
NO_FAN_RE = re.compile(r"(無風扇|不含風扇|不附風扇)", flags=re.IGNORECASE)
FAN_WORD_RE = re.compile(r"(風扇|fan)", flags=re.IGNORECASE)
PWM_RE = re.compile(r"(?<![A-Za-z0-9])PWM(?![A-Za-z0-9])", flags=re.IGNORECASE)
RGB_RE = re.compile(r"(?<![A-Za-z0-9])(A-?RGB|ARGB|RGB)(?![A-Za-z0-9])", flags=re.IGNORECASE)
M2_LEN_RE = re.compile(r"\b(22110|2280|2260|2242|2230)\b")
SOCKET_RE = re.compile(
    r"(?<![A-Za-z0-9])("
    r"LGA\s*1700|LGA\s*1851|LGA\s*1200|LGA\s*115x|LGA\s*115X|LGA\s*2011|"
    r"LGA\s*2066|LGA\s*3647|LGA\s*4677|"
    r"AM4|AM5|TR4|sTRX4|sTR5|SP6|SP5"
    r")(?![A-Za-z0-9])",
    flags=re.IGNORECASE,
)

FAN_WORDS = {
    "單扇": 1,
    "雙扇": 2,
    "三扇": 3,
    "四扇": 4,
}


def extract_cooler_height_mm(text: str) -> int | None:
    match = HEIGHT_MM_RE.search(text or "")
    if match:
        return normalize_length_mm(float(match.group(1)), "mm")
    match = HEIGHT_CM_RE.search(text or "")
    if match:
        return normalize_length_mm(float(match.group(1)), "cm")
    match = HEIGHT_NUM_RE.search(text or "")
    if match:
        return normalize_length_mm(float(match.group(1)), None, assume_cm_threshold=30)
    return None


def extract_cooler_fan_sizes(text: str) -> list[int] | None:
    candidate = text or ""
    sizes: set[int] = set()
    for match in re.finditer(r"(?i)(\d{2,3})\s*mm\s*(?:風扇|fan)", candidate):
        sizes.add(int(match.group(1)))
    for match in re.finditer(r"(?i)(\d{1,2}(?:\.\d+)?)\s*cm\s*(?:風扇|fan)", candidate):
        sizes.add(int(round(float(match.group(1)) * 10)))
    for match in re.finditer(r"(?i)(?:風扇|fan)\s*[:：]?\s*(\d{2,3})\s*mm", candidate):
        sizes.add(int(match.group(1)))
    for match in re.finditer(r"(?i)(?:風扇|fan)\s*[:：]?\s*(\d{1,2}(?:\.\d+)?)\s*cm", candidate):
        sizes.add(int(round(float(match.group(1)) * 10)))
    return sorted(sizes) if sizes else None


def extract_cooler_sockets(text: str) -> list[str] | None:
    sockets: list[str] = []
    seen: set[str] = set()
    for match in SOCKET_RE.finditer(text or ""):
        raw = match.group(1).replace(" ", "")
        key = raw.upper()
        if key == "STRX4":
            norm = "sTRX4"
        elif key == "STR5":
            norm = "sTR5"
        elif key == "LGA115X":
            norm = "LGA115x"
        else:
            norm = key
        if norm not in seen:
            seen.add(norm)
            sockets.append(norm)
    return sockets or None


def extract_cpu_air_detail_hints(line: str, full: str) -> dict[str, object]:
    details: dict[str, object] = {
        "tdp_w_hint": None,
        "height_mm_hint": extract_cooler_height_mm(line),
        "heatpipe_count_hint": None,
        "fan_count_hint": None,
        "fan_sizes_mm_hint": extract_cooler_fan_sizes(line),
        "pwm_hint": True if PWM_RE.search(full) else None,
        "rgb_hint": True if RGB_RE.search(full) else None,
        "socket_support_hint": extract_cooler_sockets(full),
    }

    match = TDP_RE.search(line)
    if match:
        details["tdp_w_hint"] = int(match.group(1))

    match = HEATPIPE_COUNT_RE.search(full)
    if match:
        details["heatpipe_count_hint"] = int(match.group("n"))

    for word, count in FAN_WORDS.items():
        if word in line:
            details["fan_count_hint"] = count
            break
    if details["fan_count_hint"] is None:
        match = FAN_MULT_RE.search(line)
        if match:
            details["fan_count_hint"] = int(match.group(1))
    if details["fan_count_hint"] is None:
        match = FAN_COUNT_RE.search(line)
        if match:
            details["fan_count_hint"] = int(match.group(1))
    if details["fan_count_hint"] is None and FAN_WORD_RE.search(line) and not NO_FAN_RE.search(line):
        details["fan_count_hint"] = 1
    return details


def extract_cpu_liquid_detail_hints(full: str) -> dict[str, object]:
    return {
        "pwm_hint": True if PWM_RE.search(full) else None,
        "rgb_hint": True if RGB_RE.search(full) else None,
        "socket_support_hint": extract_cooler_sockets(full),
    }


def extract_notebook_cooler_detail_hints(full: str) -> dict[str, object]:
    return {
        "rgb_hint": True if RGB_RE.search(full) else None,
    }


def extract_ssd_heatsink_detail_hints(full: str) -> dict[str, object]:
    details: dict[str, object] = {
        "m2_length_hint": None,
        "heatpipe_count_hint": None,
        "fan_count_hint": None,
        "fan_sizes_mm_hint": extract_cooler_fan_sizes(full),
        "pwm_hint": True if PWM_RE.search(full) else None,
        "rgb_hint": True if RGB_RE.search(full) else None,
    }

    match = M2_LEN_RE.search(full)
    if match:
        details["m2_length_hint"] = int(match.group(1))
    match = HEATPIPE_COUNT_RE.search(full)
    if match:
        details["heatpipe_count_hint"] = int(match.group("n"))
    if FAN_WORD_RE.search(full) and not NO_FAN_RE.search(full):
        details["fan_count_hint"] = 1
        match = FAN_MULT_RE.search(full)
        if match:
            details["fan_count_hint"] = int(match.group(1))
    return details


__all__ = [
    "extract_cooler_fan_sizes",
    "extract_cooler_height_mm",
    "extract_cooler_sockets",
    "extract_cpu_air_detail_hints",
    "extract_cpu_liquid_detail_hints",
    "extract_notebook_cooler_detail_hints",
    "extract_ssd_heatsink_detail_hints",
]
