from __future__ import annotations

import re

from ..common import head_before_brackets
from ..shared_specs import extract_limit_hint
from .case_clearance_specs import (
    collect_case_form_factors,
    extract_case_dimensions_mm,
    extract_case_labeled_length_from_lines,
    extract_case_labeled_length_mm,
    extract_case_mb_form_factor,
    extract_case_radiator_support,
    pick_case_form_factor,
)
from .case_layout_specs import (
    collect_case_text_lines,
    extract_case_drive_bays,
    extract_case_psu_included,
    extract_case_psu_watt,
    extract_case_side_panel,
    has_case_psu_bundle,
    normalize_case_fan_support,
)

_GPU_LABEL_RE = re.compile(r"(?:(顯卡長|卡長)|(?<![\u4e00-\u9fff])卡)\s*[:：]?\s*", flags=re.IGNORECASE)
_CPU_LABEL_RE = re.compile(r"(CPU散熱器高|CPU高|U高)\s*[:：]?\s*", flags=re.IGNORECASE)
_BUNDLE_RE = re.compile(r"(大全配|套裝|組合|bundle)", flags=re.IGNORECASE)
_LIMIT_RE = re.compile(r"(限組裝|限購|限量|客訂)", flags=re.IGNORECASE)
_ACCESSORY_RE = re.compile(r"(配件|支架|扣具)", flags=re.IGNORECASE)
_CASE_LIKE_RE = re.compile(
    r"(?i)(顯卡長|卡長|CPU高|U高|水冷|風扇支援|前I/O|尺寸|"
    r"E-?ATX|ATX|M-?ATX|Micro-ATX|Mini-ITX|ITX|玻璃|透側|機殼|電源)"
)
_MODEL_BUNDLE_SPLIT_RE = re.compile(r"\s+[+＋]\s+")


def extract_case_spec_hints(
    *,
    line: str,
    lines: list[str],
    head: str,
    clean_line: str,
) -> dict[str, object]:
    mb_form_factor_support_hint = extract_case_mb_form_factor(lines) or extract_case_mb_form_factor([line])
    gpu_title_value = extract_case_labeled_length_mm(line, _GPU_LABEL_RE)
    gpu_desc_value = extract_case_labeled_length_from_lines(lines, _GPU_LABEL_RE)
    if gpu_title_value is not None and gpu_desc_value is not None:
        gpu_max_length_mm_hint = max(gpu_title_value, gpu_desc_value)
    else:
        gpu_max_length_mm_hint = gpu_title_value if gpu_title_value is not None else gpu_desc_value

    cpu_title_value = extract_case_labeled_length_mm(line, _CPU_LABEL_RE)
    cpu_desc_value = extract_case_labeled_length_from_lines(lines, _CPU_LABEL_RE)
    if cpu_title_value is not None and cpu_desc_value is not None:
        cpu_cooler_max_height_mm_hint = max(cpu_title_value, cpu_desc_value)
    else:
        cpu_cooler_max_height_mm_hint = cpu_title_value if cpu_title_value is not None else cpu_desc_value

    radiator_support_mm_hint, seen_support = extract_case_radiator_support(lines)
    if radiator_support_mm_hint is None and not seen_support:
        radiator_support_mm_hint, _seen = extract_case_radiator_support([line])

    dimensions_mm_hint = extract_case_dimensions_mm(lines)
    if dimensions_mm_hint is None:
        dimensions_mm_hint = extract_case_dimensions_mm([line])

    side_panel_hint = extract_case_side_panel(" ".join(lines)) or extract_case_side_panel(line)
    drive_bays_hint = extract_case_drive_bays(lines) or extract_case_drive_bays([line])
    included_fans_hint = collect_case_text_lines(lines, "內附風扇") or collect_case_text_lines([line], "內附風扇")
    fan_support_hint = collect_case_text_lines(lines, "風扇支援") or collect_case_text_lines([line], "風扇支援")
    front_io_hint = collect_case_text_lines(lines, "前I/O") or collect_case_text_lines([line], "前I/O")
    fan_support_hint = normalize_case_fan_support(fan_support_hint)

    psu_included_hint = extract_case_psu_included(lines) or extract_case_psu_included([line])
    psu_watt_w_hint = extract_case_psu_watt(lines) or extract_case_psu_watt([line])
    if psu_watt_w_hint is not None and psu_included_hint is None:
        psu_included_hint = True

    limit_hint = extract_limit_hint(lines or [line], _LIMIT_RE)
    bundle_blob = " ".join([line] + lines)
    is_bundle = bool(
        _BUNDLE_RE.search(head)
        or has_case_psu_bundle(bundle_blob)
        or _MODEL_BUNDLE_SPLIT_RE.search(line)
    )

    accessory_text = head_before_brackets(clean_line) or clean_line
    blob = " ".join([line] + lines)
    is_accessory = True if (_ACCESSORY_RE.search(accessory_text) and not _CASE_LIKE_RE.search(blob)) else None

    return {
        "mb_form_factor_support_hint": mb_form_factor_support_hint,
        "gpu_max_length_mm_hint": gpu_max_length_mm_hint,
        "cpu_cooler_max_height_mm_hint": cpu_cooler_max_height_mm_hint,
        "radiator_support_mm_hint": radiator_support_mm_hint,
        "dimensions_mm_hint": dimensions_mm_hint,
        "side_panel_hint": side_panel_hint,
        "drive_bays_hint": drive_bays_hint,
        "included_fans_hint": included_fans_hint,
        "fan_support_hint": fan_support_hint,
        "front_io_hint": front_io_hint,
        "psu_included_hint": psu_included_hint,
        "psu_watt_w_hint": psu_watt_w_hint,
        "limit_hint": limit_hint,
        "is_bundle": is_bundle,
        "is_accessory": is_accessory,
    }


__all__ = [
    "collect_case_form_factors",
    "extract_case_dimensions_mm",
    "extract_case_labeled_length_from_lines",
    "extract_case_labeled_length_mm",
    "extract_case_mb_form_factor",
    "extract_case_psu_included",
    "extract_case_psu_watt",
    "extract_case_radiator_support",
    "extract_case_side_panel",
    "extract_case_spec_hints",
    "pick_case_form_factor",
]
