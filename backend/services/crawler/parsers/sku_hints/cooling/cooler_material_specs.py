from __future__ import annotations

import re

PAD_THICKNESS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*mm(?:\(|（)?\s*厚", flags=re.IGNORECASE)
PAD_DIM_RE = re.compile(r"(\d+(?:\.\d+)?)\s*[xX×]\s*(\d+(?:\.\d+)?)\s*mm", flags=re.IGNORECASE)
THERMAL_COND_RE = re.compile(r"(\d+(?:\.\d+)?)\s*W\s*/\s*m\s*-?\s*K", flags=re.IGNORECASE)
WEIGHT_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(?:公克|g)\b", flags=re.IGNORECASE)
ANY_MM_RE = re.compile(r"(\d+(?:\.\d+)?)\s*mm", flags=re.IGNORECASE)


def extract_cooler_pad_thickness(text: str) -> float | None:
    match = PAD_THICKNESS_RE.search(text or "")
    if match:
        return float(match.group(1))
    match = ANY_MM_RE.search(text or "")
    if match:
        return float(match.group(1))
    return None


def extract_cooler_pad_dimensions(text: str) -> str | None:
    match = PAD_DIM_RE.search(text or "")
    if not match:
        return None
    return f"{match.group(1)}x{match.group(2)}"


def extract_cooler_thermal_conductivity(text: str) -> float | None:
    match = THERMAL_COND_RE.search(text or "")
    return float(match.group(1)) if match else None


def extract_cooler_weight(text: str) -> float | None:
    match = WEIGHT_RE.search(text or "")
    return float(match.group(1)) if match else None


def extract_thermal_pad_detail_hints(line: str) -> dict[str, object]:
    return {
        "pad_thickness_mm_hint": extract_cooler_pad_thickness(line),
        "pad_dimensions_mm_hint": extract_cooler_pad_dimensions(line),
        "thermal_conductivity_w_mk_hint": extract_cooler_thermal_conductivity(line),
    }


def extract_thermal_paste_detail_hints(line: str) -> dict[str, object]:
    return {
        "thermal_conductivity_w_mk_hint": extract_cooler_thermal_conductivity(line),
        "weight_g_hint": extract_cooler_weight(line),
    }


__all__ = [
    "extract_cooler_pad_dimensions",
    "extract_cooler_pad_thickness",
    "extract_cooler_thermal_conductivity",
    "extract_cooler_weight",
    "extract_thermal_pad_detail_hints",
    "extract_thermal_paste_detail_hints",
]
