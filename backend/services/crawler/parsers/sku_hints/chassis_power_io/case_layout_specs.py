# backend/services/crawler/parsers/sku_hints/chassis_power_io/case_layout_specs.py
from __future__ import annotations

import re

from ..common import normalize_spaces

SIDE_TG_RE = re.compile(r"(玻璃|鋼化玻璃|TG|透側)", flags=re.IGNORECASE)
SIDE_ACRYLIC_RE = re.compile(r"(壓克力|Acrylic)", flags=re.IGNORECASE)
SIDE_SOLID_RE = re.compile(r"(無側透|鐵側板|金屬側板|網孔|Solid|靜音側板|隔音側板|靜音)", flags=re.IGNORECASE)
DRIVE_BAY_RE = re.compile(r"(5\.25|3\.5|2\.5)\s*[*x×]\s*(\d+)", flags=re.IGNORECASE)
DRIVE_BAY_SSD_RE = re.compile(r"(?<![A-Za-z0-9])SSD\s*[*x×]\s*(\d+)", flags=re.IGNORECASE)
DRIVE_BAY_HDD_RE = re.compile(r"(?<![A-Za-z0-9])HDD\s*[*x×]\s*(\d+)", flags=re.IGNORECASE)
DRIVE_HOTSWAP_RE = re.compile(r"(?<!\d)(\d+)\s*[*x×]\s*硬碟熱插拔")
PSU_INCLUDED_RE = re.compile(
    r"(含電源|機殼\+電源|內附\s*\d{2,4}\s*W?\s*(?:\S+\s*){0,2}電源)",
    flags=re.IGNORECASE,
)
PSU_WATT_RE = re.compile(r"(\d{2,4})\s*W", flags=re.IGNORECASE)


def extract_case_side_panel(text: str) -> str | None:
    if SIDE_TG_RE.search(text or ""):
        return "TG"
    if SIDE_ACRYLIC_RE.search(text or ""):
        return "Acrylic"
    if SIDE_SOLID_RE.search(text or ""):
        return "Solid"
    return None


def extract_case_drive_bays(lines: list[str]) -> dict[str, int] | None:
    for line in lines:
        if not any(keyword in line for keyword in ("硬碟空間", "硬碟位", "SSD", "HDD", "熱插拔")):
            continue
        content = line
        if "：" in content:
            content = content.split("：", 1)[1]
        elif ":" in content:
            content = content.split(":", 1)[1]
        content = re.sub(r"\([^)]*\)", "", content)
        if re.search(r"\bor\b|或", content, flags=re.IGNORECASE):
            return None
        result: dict[str, int] = {}
        for size, count in DRIVE_BAY_RE.findall(content):
            number = int(count)
            previous = result.get(size)
            result[size] = number if previous is None else max(previous, number)
        match = DRIVE_BAY_SSD_RE.search(content)
        if match:
            number = int(match.group(1))
            previous = result.get("2.5")
            result["2.5"] = number if previous is None else max(previous, number)
        match = DRIVE_BAY_HDD_RE.search(content)
        if match:
            number = int(match.group(1))
            previous = result.get("3.5")
            result["3.5"] = number if previous is None else max(previous, number)
        match = DRIVE_HOTSWAP_RE.search(content)
        if match:
            number = int(match.group(1))
            previous = result.get("3.5")
            result["3.5"] = number if previous is None else max(previous, number)
        if result:
            return result
    return None


def collect_case_text_lines(lines: list[str], keyword: str) -> str | None:
    hits = [normalize_spaces(line) for line in lines if keyword in line]
    if not hits:
        return None
    return " / ".join(hits)


def normalize_case_fan_support(text: str | None) -> str | None:
    if not text:
        return text
    text = re.sub(r"(?<!\d)12\*14\*(\d+)", r"12/14*\1", text)
    text = re.sub(r"(?<!\d)14\*12\*(\d+)", r"12/14*\1", text)
    return text


def extract_case_psu_included(lines: list[str]) -> bool | None:
    for line in lines:
        if PSU_INCLUDED_RE.search(line):
            return True
    return None


def extract_case_psu_watt(lines: list[str]) -> int | None:
    for line in lines:
        if "電源" not in line and not PSU_INCLUDED_RE.search(line):
            continue
        watts = [int(match.group(1)) for match in PSU_WATT_RE.finditer(line)]
        if watts:
            return max(watts)
    return None


def has_case_psu_bundle(text: str) -> bool:
    return bool(PSU_INCLUDED_RE.search(text or ""))


__all__ = [
    "collect_case_text_lines",
    "extract_case_drive_bays",
    "extract_case_psu_included",
    "extract_case_psu_watt",
    "extract_case_side_panel",
    "has_case_psu_bundle",
    "normalize_case_fan_support",
]
