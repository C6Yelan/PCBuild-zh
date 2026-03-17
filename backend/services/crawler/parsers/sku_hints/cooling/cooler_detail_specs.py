from __future__ import annotations

from .cooler_material_specs import (
    extract_cooler_pad_dimensions,
    extract_cooler_pad_thickness,
    extract_cooler_thermal_conductivity,
    extract_cooler_weight,
    extract_thermal_pad_detail_hints,
    extract_thermal_paste_detail_hints,
)
from .cooler_support_specs import (
    extract_cooler_fan_sizes,
    extract_cooler_height_mm,
    extract_cooler_sockets,
    extract_cpu_air_detail_hints,
    extract_cpu_liquid_detail_hints,
    extract_notebook_cooler_detail_hints,
    extract_ssd_heatsink_detail_hints,
)


def build_cooler_detail_template() -> dict[str, object]:
    return {
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


def extract_cooler_detail_hints(
    *,
    line: str,
    full: str,
    cooler_kind_hint: str,
) -> dict[str, object]:
    details = build_cooler_detail_template()

    if cooler_kind_hint == "cpu_air":
        details.update(extract_cpu_air_detail_hints(line, full))
    elif cooler_kind_hint == "cpu_liquid_aio":
        details.update(extract_cpu_liquid_detail_hints(full))
    elif cooler_kind_hint == "notebook_cooler":
        details.update(extract_notebook_cooler_detail_hints(full))
    elif cooler_kind_hint == "ssd_heatsink":
        details.update(extract_ssd_heatsink_detail_hints(full))
    elif cooler_kind_hint == "thermal_pad":
        details.update(extract_thermal_pad_detail_hints(line))
    elif cooler_kind_hint == "thermal_paste":
        details.update(extract_thermal_paste_detail_hints(line))

    return details


__all__ = [
    "build_cooler_detail_template",
    "extract_cooler_detail_hints",
    "extract_cooler_fan_sizes",
    "extract_cooler_height_mm",
    "extract_cooler_pad_dimensions",
    "extract_cooler_pad_thickness",
    "extract_cooler_sockets",
    "extract_cooler_thermal_conductivity",
    "extract_cooler_weight",
]
