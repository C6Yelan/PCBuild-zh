from __future__ import annotations

import re

from ..common import first_line, head_before_brackets, normalize_spaces, strip_leading_note

_BRACKET_CONTENT_RE = re.compile(r"[（(【\[](?P<content>[^）)】\]]+)[）)】\]]")
_BRACKET_REMOVE_RE = re.compile(r"[（(【\[][^\)）】\]]*[）)】\]]")
_SKU_TOKEN_RE = re.compile(r"[A-Z0-9][A-Z0-9-]{5,}", flags=re.IGNORECASE)
_DDR3L_RE = re.compile(r"DDR3L", flags=re.IGNORECASE)
_DDR_RE = re.compile(r"DDR\s*([345])", flags=re.IGNORECASE)
_DDR_SHORT_RE = re.compile(r"D([345])", flags=re.IGNORECASE)
_DDR_SPEED_RE = re.compile(
    r"(?:DDR3L|DDR[345]|D[345])\s*[- ]?\s*(?P<speed>\d{3,5})(?!\d)",
    flags=re.IGNORECASE,
)
_SPEED_UNIT_RE = re.compile(r"(?P<speed>\d{3,5})\s*(?:MT/s|MHz)(?!\d)", flags=re.IGNORECASE)
_CAPACITY_RE = re.compile(r"(?<!\d)(?P<gb>\d{1,3})\s*G(?:B)?(?!\d)", flags=re.IGNORECASE)
_KIT_RE = re.compile(
    r"(?P<per>\d{1,3})\s*G(?:B)?\s*[*xX×]\s*(?P<count>\d{1,2})(?!\d)",
    flags=re.IGNORECASE,
)
_CL_RE = re.compile(r"CL\s*(?P<cl>\d{2,3})(?!\d)", flags=re.IGNORECASE)
_CL_CODE_RE = re.compile(r"C(?P<cl>\d{2,3})(?!\d)", flags=re.IGNORECASE)
_XMP_RE = re.compile(r"\bXMP\b", flags=re.IGNORECASE)
_EXPO_RE = re.compile(r"\bEXPO\b", flags=re.IGNORECASE)
_RGB_ARGB_RE = re.compile(r"ARGB|RGB", flags=re.IGNORECASE)
_FORM_FACTOR_RE = re.compile(r"\bSO-?DIMM\b|\bSODIMM\b|\bUDIMM\b|\bRDIMM\b", flags=re.IGNORECASE)
_ECC_RE = re.compile(r"\bECC\b|\bREGISTERED\b|\bREG\b|\bRDIMM\b", flags=re.IGNORECASE)
_ACCESSORY_RE = re.compile(
    r"(記憶體散熱器|記憶體散熱|記憶體風扇|RAM\s*COOLER|MEMORY\s*COOLER|RAM\s*FAN|MEMORY\s*FAN)",
    flags=re.IGNORECASE,
)
_TRAILING_TAG_RE = re.compile(r"\bAI\b\s*$", flags=re.IGNORECASE)
_PLUS_SPLIT_RE = re.compile(r"[+＋]")
_SINGLE_RE = re.compile(r"(單條|單支|單顆)", flags=re.IGNORECASE)
_NB_RE = re.compile(r"(?<![A-Za-z0-9])NB(?![A-Za-z0-9])|筆電", flags=re.IGNORECASE)
_FIRST_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")

_BUNDLE_KEYWORDS_RE = re.compile(r"(大全配|優惠組合|組合|套餐|搭機|整機)", flags=re.IGNORECASE)
_NON_RAM_PART_RE = re.compile(
    r"(主機板|CPU|處理器|顯卡|SSD|硬碟|HDD|電源|機殼|散熱|水冷|風扇|電源供應器)",
    flags=re.IGNORECASE,
)

_MAKER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:\bBIWIN\b|佰維)", flags=re.IGNORECASE), "BIWIN"),
    (re.compile(r"(?:\bCORSAIR\b|海盜船)", flags=re.IGNORECASE), "CORSAIR"),
    (re.compile(r"(?:\bACER\b)", flags=re.IGNORECASE), "ACER"),
    (re.compile(r"(?:\bKINGSTON\b|金士頓)", flags=re.IGNORECASE), "KINGSTON"),
    (re.compile(r"(?:\bG\.?SKILL\b|芝奇)", flags=re.IGNORECASE), "G.SKILL"),
    (re.compile(r"(?:\bADATA\b|威剛)", flags=re.IGNORECASE), "ADATA"),
    (re.compile(r"(?:\bTEAMGROUP\b|\bTEAM\b|十銓)", flags=re.IGNORECASE), "TEAMGROUP"),
    (re.compile(r"(?:\bCRUCIAL\b|\bMICRON\b|美光)", flags=re.IGNORECASE), "MICRON"),
    (re.compile(r"(?:\bORIGIN\s*CODE\b)", flags=re.IGNORECASE), "ORIGIN CODE"),
    (re.compile(r"(?:\bAPACER\b|宇瞻)", flags=re.IGNORECASE), "APACER"),
    (re.compile(r"(?:\bKLEVV\b|科賦)", flags=re.IGNORECASE), "KLEVV"),
    (re.compile(r"(?:\bUMAX\b|宏泰|優美)", flags=re.IGNORECASE), "UMAX"),
]


def _is_bundle_head(head: str) -> bool:
    h = head or ""
    if not h:
        return False
    if _BUNDLE_KEYWORDS_RE.search(h):
        return True
    if _PLUS_SPLIT_RE.search(h) and _NON_RAM_PART_RE.search(h):
        return True
    return False


def _looks_like_part_number(token: str) -> bool:
    if not token:
        return False
    if not _SKU_TOKEN_RE.fullmatch(token):
        return False
    alpha = sum(1 for ch in token if ch.isalpha())
    digit = sum(1 for ch in token if ch.isdigit())
    if alpha < 2 or digit < 2:
        return False
    if any(ch in token for ch in ("*", "×")):
        return False
    return True


def _extract_bracket_sku(text: str) -> str | None:
    for m in _BRACKET_CONTENT_RE.finditer(text or ""):
        content = m.group("content") or ""
        for raw in re.split(r"[\s,;/|]+", content):
            token = raw.strip().strip("()[]{}")
            if _looks_like_part_number(token):
                return token
    return None


def _extract_ddr_gen(text: str) -> str | None:
    if _DDR3L_RE.search(text or ""):
        return "DDR3"
    m = _DDR_RE.search(text or "")
    if m:
        return f"DDR{m.group(1)}"
    m = _DDR_SHORT_RE.search(text or "")
    if m:
        return f"DDR{m.group(1)}"
    return None


def _extract_speed(text: str) -> int | None:
    m = _DDR_SPEED_RE.search(text or "")
    if m:
        return int(m.group("speed"))
    m = _SPEED_UNIT_RE.search(text or "")
    if m:
        return int(m.group("speed"))
    return None


def _extract_capacity(text: str) -> int | None:
    m = _CAPACITY_RE.search(text or "")
    return int(m.group("gb")) if m else None


def _extract_kit(text: str) -> tuple[int | None, int | None]:
    m = _KIT_RE.search(text or "")
    if not m:
        return None, None
    per = int(m.group("per"))
    count = int(m.group("count"))
    return per, count


def _extract_cl(text: str) -> int | None:
    m = _CL_RE.search(text or "")
    if m:
        return int(m.group("cl"))
    m = _CL_CODE_RE.search(text or "")
    return int(m.group("cl")) if m else None


def _extract_rgb(text: str) -> bool | None:
    return True if _RGB_ARGB_RE.search(text or "") else None


def _extract_form_factor(text: str) -> str | None:
    m = _FORM_FACTOR_RE.search(text or "")
    if not m:
        return None
    token = m.group(0).upper().replace(" ", "")
    if token in ("SODIMM", "SO-DIMM"):
        return "SO-DIMM"
    if token == "UDIMM":
        return "UDIMM"
    if token == "RDIMM":
        return "RDIMM"
    return token


def _infer_maker(text: str) -> str | None:
    for pat, norm in _MAKER_PATTERNS:
        if pat.search(text or ""):
            return norm
    m = _FIRST_TOKEN_RE.search(text or "")
    if not m:
        return None
    token = m.group(0)
    if not any(ch.isalpha() for ch in token):
        return None
    return token.upper()


def _clean_fallback_title(title: str) -> str:
    line = normalize_spaces(strip_leading_note(first_line(title)))
    base = _BRACKET_REMOVE_RE.sub(" ", line)
    base = normalize_spaces(base)
    base = re.sub(r"([A-Za-z])(\d)", r"\1 \2", base)
    base = re.sub(r"(\d)([A-Za-z])", r"\1 \2", base)
    if base:
        base = _PLUS_SPLIT_RE.split(base, 1)[0].strip()
    base = _TRAILING_TAG_RE.sub("", base).strip()
    return base or line


def extract_ram_hints(title: str) -> tuple[str, dict[str, object]]:
    text = title or ""
    line = normalize_spaces(strip_leading_note(first_line(text)))
    head = head_before_brackets(line)

    sku_hint = _extract_bracket_sku(line) or _clean_fallback_title(line)

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
    maker_hint = _infer_maker(line)

    xmp_hint = True if _XMP_RE.search(line) else None
    expo_hint = True if _EXPO_RE.search(line) else None
    ecc_hint = True if _ECC_RE.search(line) else None
    is_accessory = bool(_ACCESSORY_RE.search(line))
    bundle_text = normalize_spaces(_BRACKET_REMOVE_RE.sub(" ", line))
    is_bundle = _is_bundle_head(bundle_text)

    single_hint = bool(_SINGLE_RE.search(line))
    nb_hint = bool(_NB_RE.search(line)) or form_factor_hint == "SO-DIMM"
    if kit_dimms_hint is None and per_dimm_gb_hint is None and capacity_gb_hint is not None:
        if single_hint or nb_hint:
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


def extract_ram_sku_hint(title: str) -> str | None:
    sku_hint, _extra = extract_ram_hints(title)
    return sku_hint


__all__ = ["extract_ram_hints", "extract_ram_sku_hint"]
