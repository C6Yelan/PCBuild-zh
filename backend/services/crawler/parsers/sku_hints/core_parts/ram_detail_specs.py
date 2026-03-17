from __future__ import annotations

import re

from ..common import first_line, head_before_brackets, normalize_spaces, strip_leading_note
from .ram_identity_specs import (
    extract_ram_sku_hint,
    infer_ram_accessory,
    infer_ram_bundle,
    infer_ram_maker,
    infer_ram_notebook_hint,
    infer_ram_single_hint,
)

_DDR3L_RE = re.compile(r"DDR3L", flags=re.IGNORECASE)
_DDR_RE = re.compile(r"DDR\s*([345])", flags=re.IGNORECASE)
_DDR_SHORT_RE = re.compile(r"D([345])", flags=re.IGNORECASE)
_DDR_SPEED_RE = re.compile(r"(?:DDR3L|DDR[345]|D[345])\s*[- ]?\s*(?P<speed>\d{3,5})(?!\d)", flags=re.IGNORECASE)
_SPEED_UNIT_RE = re.compile(r"(?P<speed>\d{3,5})\s*(?:MT/s|MHz)(?!\d)", flags=re.IGNORECASE)
_CAPACITY_RE = re.compile(r"(?<!\d)(?P<gb>\d{1,3})\s*G(?:B)?(?!\d)", flags=re.IGNORECASE)
_KIT_RE = re.compile(r"(?P<per>\d{1,3})\s*G(?:B)?\s*[*xX×]\s*(?P<count>\d{1,2})(?!\d)", flags=re.IGNORECASE)
_CL_RE = re.compile(r"CL\s*(?P<cl>\d{2,3})(?!\d)", flags=re.IGNORECASE)
_CL_CODE_RE = re.compile(r"C(?P<cl>\d{2,3})(?!\d)", flags=re.IGNORECASE)
_XMP_RE = re.compile(r"\bXMP\b", flags=re.IGNORECASE)
_EXPO_RE = re.compile(r"\bEXPO\b", flags=re.IGNORECASE)
_RGB_ARGB_RE = re.compile(r"ARGB|RGB", flags=re.IGNORECASE)
_FORM_FACTOR_RE = re.compile(r"\bSO-?DIMM\b|\bSODIMM\b|\bUDIMM\b|\bRDIMM\b", flags=re.IGNORECASE)
_ECC_RE = re.compile(r"\bECC\b|\bREGISTERED\b|\bREG\b|\bRDIMM\b", flags=re.IGNORECASE)


def _extract_ddr_gen(text: str) -> str | None:
    if _DDR3L_RE.search(text or ""):
        return "DDR3"
    match = _DDR_RE.search(text or "")
    if match:
        return f"DDR{match.group(1)}"
    match = _DDR_SHORT_RE.search(text or "")
    if match:
        return f"DDR{match.group(1)}"
    return None


def _extract_speed(text: str) -> int | None:
    match = _DDR_SPEED_RE.search(text or "")
    if match:
        return int(match.group("speed"))
    match = _SPEED_UNIT_RE.search(text or "")
    if match:
        return int(match.group("speed"))
    return None


def _extract_capacity(text: str) -> int | None:
    match = _CAPACITY_RE.search(text or "")
    return int(match.group("gb")) if match else None


def _extract_kit(text: str) -> tuple[int | None, int | None]:
    match = _KIT_RE.search(text or "")
    if not match:
        return None, None
    return int(match.group("per")), int(match.group("count"))


def _extract_cl(text: str) -> int | None:
    match = _CL_RE.search(text or "")
    if match:
        return int(match.group("cl"))
    match = _CL_CODE_RE.search(text or "")
    return int(match.group("cl")) if match else None


def _extract_rgb(text: str) -> bool | None:
    return True if _RGB_ARGB_RE.search(text or "") else None


def _extract_form_factor(text: str) -> str | None:
    match = _FORM_FACTOR_RE.search(text or "")
    if not match:
        return None
    token = match.group(0).upper().replace(" ", "")
    if token in ("SODIMM", "SO-DIMM"):
        return "SO-DIMM"
    if token == "UDIMM":
        return "UDIMM"
    if token == "RDIMM":
        return "RDIMM"
    return token


def extract_ram_hints(title: str) -> tuple[str, dict[str, object]]:
    text = title or ""
    line = normalize_spaces(strip_leading_note(first_line(text)))
    head = head_before_brackets(line)

    sku_hint = extract_ram_sku_hint(line)
    ddr_gen_hint = _extract_ddr_gen(line)
    speed_mts_hint = _extract_speed(line)
    capacity_gb_hint = _extract_capacity(head) or _extract_capacity(line)
    per_dimm_gb_hint, kit_dimms_hint = _extract_kit(line)
    if per_dimm_gb_hint is not None and kit_dimms_hint is not None:
        total = per_dimm_gb_hint * kit_dimms_hint
        if capacity_gb_hint is None or capacity_gb_hint == per_dimm_gb_hint:
            capacity_gb_hint = total

    cl_hint = _extract_cl(line)
    rgb_hint = _extract_rgb(line)
    form_factor_hint = _extract_form_factor(line)
    maker_hint = infer_ram_maker(line)
    xmp_hint = True if _XMP_RE.search(line) else None
    expo_hint = True if _EXPO_RE.search(line) else None
    ecc_hint = True if _ECC_RE.search(line) else None
    is_accessory = infer_ram_accessory(line)
    is_bundle = infer_ram_bundle(line)

    if kit_dimms_hint is None and per_dimm_gb_hint is None and capacity_gb_hint is not None:
        if infer_ram_single_hint(line) or infer_ram_notebook_hint(line, form_factor_hint):
            kit_dimms_hint = 1
            per_dimm_gb_hint = capacity_gb_hint

    extra = {
        "maker_hint": maker_hint,
        "ddr_gen_hint": ddr_gen_hint,
        "speed_mts_hint": speed_mts_hint,
        "capacity_gb_hint": capacity_gb_hint,
        "kit_dimms_hint": kit_dimms_hint,
        "per_dimm_gb_hint": per_dimm_gb_hint,
        "cl_hint": cl_hint,
        "xmp_hint": xmp_hint,
        "expo_hint": expo_hint,
        "rgb_hint": rgb_hint,
        "form_factor_hint": form_factor_hint,
        "ecc_hint": ecc_hint,
        "is_bundle": is_bundle,
        "is_accessory": is_accessory,
    }
    return sku_hint, extra
