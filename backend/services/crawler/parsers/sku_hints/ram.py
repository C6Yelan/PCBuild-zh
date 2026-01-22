# backend/services/crawler/parsers/sku_hints/ram.py
from __future__ import annotations

import re

from .common import (
    compact_extra,
    first_line,
    head_before_brackets,
    normalize_spaces,
    strip_leading_note,
)

_MAKER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\bKINGSTON\b|金士頓"), "Kingston"),
    (re.compile(r"(?i)\bG\.?SKILL\b|芝奇"), "G.SKILL"),
    (re.compile(r"(?i)\bCORSAIR\b|海盜船"), "Corsair"),
    (re.compile(r"(?i)\bCRUCIAL\b|美光"), "Crucial"),
    (re.compile(r"(?i)\bADATA\b|威剛"), "ADATA"),
    (re.compile(r"(?i)\bXPG\b"), "ADATA"),
    (re.compile(r"(?i)\bTEAMGROUP\b|\bTEAM\s*GROUP\b|十銓"), "TeamGroup"),
    (re.compile(r"(?i)\bT-?FORCE\b"), "TeamGroup"),
    (re.compile(r"(?i)\bUMAX\b"), "UMAX"),
    (re.compile(r"(?i)\bBIWIN\b|佰維"), "Biwin"),
    (re.compile(r"(?i)\bKINGBANK\b|金百達"), "KingBank"),
    (re.compile(r"(?i)\bKLEVV\b|科賦"), "KLEVV"),
    (re.compile(r"(?i)\bPATRIOT\b|博帝"), "Patriot"),
    (re.compile(r"(?i)\bGEIL\b|金邦"), "GeIL"),
    (re.compile(r"(?i)\bAPACER\b|宇瞻"), "Apacer"),
    (re.compile(r"(?i)\bTRANSCEND\b|創見"), "Transcend"),
    (re.compile(r"(?i)\bSAMSUNG\b|三星"), "Samsung"),
    (re.compile(r"(?i)\bMICRON\b"), "Micron"),
]

_DDR_RE = re.compile(r"(?i)\bDDR\s*(?P<gen>[345])(?:L)?\b")
_DDR_SPEED_RE = re.compile(
    r"(?i)\bDDR\s*(?P<gen>[345])(?:L)?\s*[- ]\s*(?P<mhz>\d{3,5})"
)
_D_GEN_RE = re.compile(r"(?i)(?<![A-Za-z0-9])D(?P<gen>[345])(?=[^A-Za-z0-9]|$)")
_D_SPEED_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])D(?P<gen>[345])\s*[- ]\s*(?P<mhz>\d{3,5})"
)
_SPEED_RE = re.compile(r"(?i)\b(?P<mhz>\d{3,5})\s*(?:MHZ|MT/S|MTS|MT\/S)\b")
_CL_RE = re.compile(r"(?i)CL\s*(?P<cl>\d{2,3})")

_CAPACITY_KIT_RE = re.compile(
    r"(?i)(?<!\d)(?P<per>\d{1,3})\s*G(?:B)?\s*[xX*]\s*(?P<kit>\d{1,2})"
)
_CAPACITY_KIT_REV_RE = re.compile(
    r"(?i)(?<!\d)(?P<kit>\d{1,2})\s*[xX*]\s*(?P<per>\d{1,3})\s*G(?:B)?"
)
_TOTAL_GB_RE = re.compile(
    r"(?i)(?<!\d)(?P<total>\d{1,3})\s*G(?:B)?(?!\s*[xX*])(?![A-Za-z])"
)

_FORM_FACTOR_RDIMM_RE = re.compile(r"(?i)\bRDIMM\b|\bREG(?:ISTERED)?\b")
_FORM_FACTOR_SODIMM_RE = re.compile(r"(?i)\bSO-?DIMM\b|\bSODIMM\b|\bNB\b")
_FORM_FACTOR_UDIMM_RE = re.compile(r"(?i)\bUDIMM\b|\bDIMM\b")
_XMP_RE = re.compile(r"(?i)XMP")
_EXPO_RE = re.compile(r"(?i)EXPO")
_RGB_RE = re.compile(r"(?i)ARGB|RGB")
_ECC_NEG_RE = re.compile(r"(?i)\bNON[-\s]*ECC\b")
_ECC_POS_RE = re.compile(r"(?i)\bECC\b|\bRDIMM\b|\bREGISTERED\b|\bREG(?:ISTERED)?\b")

_ACCESSORY_RE = re.compile(
    r"(?i)(記憶體散熱器|記憶體散熱片|記憶體散熱|記憶體導熱片|記憶體風扇|"
    r"RAM\s*(?:COOLER|FAN|HEATSINK)|RAM\s*散熱|RAM\s*導熱片|"
    r"MEMORY\s*(?:COOLER|FAN|HEATSINK)|散熱風扇套件)"
)
_BUNDLE_RE = re.compile(r"(?i)(大全配|套裝|優惠組合|組合|bundle)")
_BRACKET_MODEL_RE = re.compile(r"[（(【]\s*(?P<code>[A-Za-z0-9-]+)\s*[）)】]")
_SINGLE_STICK_RE = re.compile(r"(單條|單支)")

_SPEC_STRIP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\bDDR\s*[345](?:L)?\s*[- ]\s*\d{3,5}\b"),
    re.compile(r"(?i)\bDDR\s*[345](?:L)?\b"),
    re.compile(r"(?i)\bD\s*[345]\s*[- ]\s*\d{3,5}\b"),
    re.compile(r"(?i)\bD\s*[345]\b"),
    re.compile(r"(?i)\b\d{3,5}\s*(?:MHZ|MT/S|MTS|MT\/S)\b"),
    re.compile(r"(?i)CL\s*\d{2,3}"),
    re.compile(r"(?i)\d{1,3}\s*G(?:B)?\s*[xX*]\s*\d{1,2}"),
    re.compile(r"(?i)\d{1,2}\s*[xX*]\s*\d{1,3}\s*G(?:B)?"),
    re.compile(r"(?i)\d{1,3}\s*G(?:B)?"),
    re.compile(r"(雙通|四通|單通|單條|單支)"),
    re.compile(r"(?i)XMP"),
    re.compile(r"(?i)EXPO"),
    re.compile(r"(?i)ARGB"),
    re.compile(r"(?i)RGB"),
    re.compile(r"(?i)\bSO-?DIMM\b|\bSODIMM\b|\bUDIMM\b|\bRDIMM\b"),
    re.compile(r"(?i)\bECC\b|\bREGISTERED\b|\bREG(?:ISTERED)?\b"),
    re.compile(r"(?i)\bRAM\b|\bMEMORY\b"),
]


def _extract_maker_hint(text: str) -> str | None:
    for pat, norm in _MAKER_PATTERNS:
        if pat.search(text or ""):
            return norm
    return None


def _extract_bracket_model_hint(text: str) -> str | None:
    for m in _BRACKET_MODEL_RE.finditer(text or ""):
        code = m.group("code")
        if len(code) < 5:
            continue
        if not re.search(r"[A-Za-z]", code) or not re.search(r"\d", code):
            continue
        return code
    return None


def _extract_ddr_speed(text: str) -> tuple[int | None, int | None]:
    for pat in (_DDR_SPEED_RE, _D_SPEED_RE):
        m = pat.search(text or "")
        if m:
            return int(m.group("gen")), int(m.group("mhz"))
    return None, None


def _extract_ddr_gen(text: str) -> int | None:
    m = _DDR_RE.search(text or "")
    if m:
        return int(m.group("gen"))
    m = _D_GEN_RE.search(text or "")
    return int(m.group("gen")) if m else None


def _extract_speed_mhz(text: str) -> int | None:
    for pat in (_DDR_SPEED_RE, _D_SPEED_RE, _SPEED_RE):
        m = pat.search(text or "")
        if m:
            return int(m.group("mhz"))
    return None


def _extract_capacity(text: str) -> tuple[int | None, int | None, int | None]:
    m = _CAPACITY_KIT_RE.search(text or "")
    if m:
        per = int(m.group("per"))
        kit = int(m.group("kit"))
        return per * kit, kit, per
    m = _CAPACITY_KIT_REV_RE.search(text or "")
    if m:
        kit = int(m.group("kit"))
        per = int(m.group("per"))
        return per * kit, kit, per
    totals = [int(m.group("total")) for m in _TOTAL_GB_RE.finditer(text or "")]
    if totals:
        return totals[0], None, None
    return None, None, None


def _extract_cl(text: str) -> int | None:
    m = _CL_RE.search(text or "")
    return int(m.group("cl")) if m else None


def _extract_form_factor(text: str) -> str | None:
    if _FORM_FACTOR_RDIMM_RE.search(text or ""):
        return "RDIMM"
    if _FORM_FACTOR_SODIMM_RE.search(text or ""):
        return "SO-DIMM"
    if _FORM_FACTOR_UDIMM_RE.search(text or ""):
        return "UDIMM"
    return None


def _extract_ecc_hint(text: str) -> bool | None:
    if _ECC_NEG_RE.search(text or ""):
        return False
    if _ECC_POS_RE.search(text or ""):
        return True
    return None


def _clean_head_for_sku(text: str) -> str | None:
    if not text:
        return None
    cleaned = text
    for pat in _SPEC_STRIP_PATTERNS:
        cleaned = pat.sub(" ", cleaned)
    cleaned = normalize_spaces(cleaned).strip(" -_/|")
    if not cleaned:
        return None
    tokens = [t for t in cleaned.split(" ") if t]
    if len(tokens) == 1 and len(tokens[0]) < 3 and not any(ch.isdigit() for ch in tokens[0]):
        return None
    return " ".join(tokens)


def extract_ram_hints(title: str) -> tuple[str | None, dict[str, object]]:
    full_text = title or ""
    line = normalize_spaces(strip_leading_note(first_line(full_text)))
    head = head_before_brackets(line)

    maker_hint = _extract_maker_hint(line)
    ddr_gen_hint, speed_mhz_hint = _extract_ddr_speed(line)
    if ddr_gen_hint is None:
        ddr_gen_hint = _extract_ddr_gen(line)
    if speed_mhz_hint is None:
        speed_mhz_hint = _extract_speed_mhz(line)
    capacity_gb_hint, kit_dimms_hint, per_dimm_gb_hint = _extract_capacity(line)
    if capacity_gb_hint is None and kit_dimms_hint and per_dimm_gb_hint:
        capacity_gb_hint = kit_dimms_hint * per_dimm_gb_hint
    if (
        kit_dimms_hint is None
        and per_dimm_gb_hint is None
        and capacity_gb_hint is not None
        and _SINGLE_STICK_RE.search(line)
    ):
        kit_dimms_hint = 1
        per_dimm_gb_hint = capacity_gb_hint
    cl_hint = _extract_cl(line)
    form_factor_hint = _extract_form_factor(line)
    ecc_hint = _extract_ecc_hint(line)

    xmp_hint = True if _XMP_RE.search(line or "") else None
    expo_hint = True if _EXPO_RE.search(line or "") else None
    rgb_hint = True if _RGB_RE.search(line or "") else None

    has_ram_signature = bool(ddr_gen_hint or speed_mhz_hint or capacity_gb_hint)
    is_accessory = bool(_ACCESSORY_RE.search(line or "")) and not has_ram_signature
    is_bundle = bool(_BUNDLE_RE.search(head or "")) or ("+" in (head or ""))

    sku_hint = _extract_bracket_model_hint(line)
    if sku_hint is None:
        sku_hint = _clean_head_for_sku(head)

    extra = compact_extra(
        {
            "maker_hint": maker_hint,
            "ddr_gen_hint": ddr_gen_hint,
            "speed_mhz_hint": speed_mhz_hint,
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
    )
    return sku_hint, extra


def extract_ram_sku_hint(title: str) -> str | None:
    sku_hint, _extra = extract_ram_hints(title)
    return sku_hint
