# backend/services/crawler/parsers/sku_hints/gpu.py
from __future__ import annotations

import re

from .common import first_line, head_before_brackets, normalize_spaces, strip_leading_note

_RTX_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])RTX\s*(?P<num>\d{3,4})"
    r"(?:\s*(?P<suffix>TI\s*SUPER|SUPER\s*TI|TI|SUPER))?"
    r"(?=[^A-Za-z0-9]|$)"
)
_RTX_A_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])RTX\s*A(?P<num>\d{3,4})(?=[^A-Za-z0-9]|$)"
)
_RTX_PRO_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])RTX\s*PRO\s*(?P<num>\d{4})(?=[^A-Za-z0-9]|$)"
)
_RX_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])RX\s*(?P<num>\d{4})(?:\s*(?P<suffix>XTX|XT))?"
    r"(?=[^A-Za-z0-9]|$)"
)
_ARC_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])ARC\s*(?P<series>[AB])\s*(?P<num>\d{3,4})(?=[^A-Za-z0-9]|$)"
)
_GT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])GT\s*(?P<num>210|710|730|1030)(?=[^A-Za-z0-9]|$)"
)
_N_GT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])N(?P<num>210|710|730)(?=[^A-Za-z0-9]|$)"
)
_AMD_PRO_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:RADEON\s+)?AI\s+PRO\s+R(?P<num>\d{4})(?=[^A-Za-z0-9]|$)"
)
_RADEON_R79_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])RADEON\s+R(?P<series>[79])\s*(?P<num>\d{3,4})(?P<suffix>X2|X)?"
    r"(?=[^A-Za-z0-9]|$)"
)
_VRAM_GB_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?P<gb>\d{1,2})\s*G(?:B)?(?=[^A-Za-z0-9]|$)"
)
_VRAM_GBD_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?P<gb>\d{1,2})\s*GBD\d(?=[^A-Za-z0-9]|$)"
)
_VRAM_GD_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?P<gb>\d{1,2})\s*GD\d(?=[^A-Za-z0-9]|$)"
)
_VRAM_O_G_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])O(?P<gb>\d{1,2})G(?=[^A-Za-z0-9]|$)"
)
_ACCESSORY_RE = re.compile(
    r"(?i)(支撐架|支架|支撐|顯示卡支架|GPU\s*holder|holder|bracket|Herculx|"
    r"轉接線|轉接頭|轉接器|轉接|轉換線|延長線|線材)"
)
_AIB_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\bASUS\b|華碩"), "ASUS"),
    (re.compile(r"(?i)\bMSI\b|微星"), "MSI"),
    (re.compile(r"(?i)\bGIGABYTE\b|技嘉"), "GIGABYTE"),
    (re.compile(r"(?i)\bZOTAC\b|索泰"), "ZOTAC"),
    (re.compile(r"(?i)\bACER\b|宏碁"), "Acer"),
    (re.compile(r"(?i)\bINNO3D\b"), "INNO3D"),
    (re.compile(r"(?i)\bSAPPHIRE\b|藍寶石"), "Sapphire"),
    (re.compile(r"(?i)\bPOWER\s*COLOR\b|撼訊"), "PowerColor"),
    (re.compile(r"(?i)\bLEADTEK\b|麗臺"), "Leadtek"),
    (re.compile(r"(?i)\bASROCK\b|華擎"), "ASRock"),
    (re.compile(r"(?i)\bINTEL\b"), "Intel"),
]
_VENDOR_RE = re.compile(r"(?i)\b(NVIDIA|AMD|RADEON|INTEL|GEFORCE)\b")
_SPEC_TOKEN_RE = re.compile(
    r"(?i)^(?:\d{1,2}G(?:B)?|\d{2,3}BIT|GDDR\d|DDR\d|HDMI|DVI|VGA|DP|"
    r"DISPLAYPORT|LOW|PROFILE|LP|PCI-?E\d?|BLACKWELL|MAX-?Q)$"
)
_CHIP_REMOVE_PATTERNS: list[re.Pattern[str]] = [
    _RTX_PRO_RE,
    _RTX_A_RE,
    _RTX_RE,
    _RX_RE,
    _ARC_RE,
    _GT_RE,
    _AMD_PRO_RE,
    _RADEON_R79_RE,
]


def _normalize_rtx(match: re.Match[str]) -> str:
    num = match.group("num")
    suffix = (match.group("suffix") or "").upper()
    has_ti = "TI" in suffix
    has_super = "SUPER" in suffix
    parts = ["RTX", num]
    if has_ti:
        parts.append("TI")
    if has_super:
        parts.append("SUPER")
    return " ".join(parts)


def _normalize_rx(match: re.Match[str]) -> str:
    num = match.group("num")
    suffix = (match.group("suffix") or "").upper()
    parts = ["RX", num]
    if suffix:
        parts.append(suffix)
    return " ".join(parts)


def _normalize_arc(match: re.Match[str]) -> str:
    series = match.group("series").upper()
    num = match.group("num")
    return f"ARC {series}{num}"

def _normalize_gt(match: re.Match[str]) -> str:
    num = match.group("num")
    return f"GT {num}"

def _normalize_n_gt(match: re.Match[str]) -> str:
    num = match.group("num")
    return f"GT {num}"

def _normalize_amd_pro(match: re.Match[str]) -> str:
    num = match.group("num")
    return f"Radeon AI PRO R{num}"

def _normalize_radeon_r79(match: re.Match[str]) -> str:
    series = match.group("series")
    num = match.group("num")
    suffix = (match.group("suffix") or "").upper()
    chip = f"Radeon R{series} {num}"
    if suffix:
        chip = f"{chip}{suffix}"
    return chip

def _normalize_rtx_a(match: re.Match[str]) -> str:
    num = match.group("num")
    return f"RTX A{num}"

def _normalize_rtx_pro(match: re.Match[str]) -> str:
    num = match.group("num")
    return f"RTX PRO {num}"

def _extract_aib_hint(text: str) -> str | None:
    for pat, norm in _AIB_PATTERNS:
        if pat.search(text or ""):
            return norm
    return None

def _strip_aib(text: str) -> str:
    for pat, _norm in _AIB_PATTERNS:
        text = pat.sub(" ", text)
    return text

def _strip_chip(text: str) -> str:
    for pat in _CHIP_REMOVE_PATTERNS:
        text = pat.sub(" ", text)
    return text

def _normalize_model_separators(text: str) -> str:
    if not text:
        return text
    text = re.sub(r"\s*-\s*-\s*", "-", text)
    text = re.sub(r"-{2,}", "-", text)
    return text

def _is_spec_token(token: str) -> bool:
    if not token:
        return False
    if _SPEC_TOKEN_RE.match(token):
        return True
    if re.search(r"(?i)GDDR|DDR", token):
        return True
    if re.search(r"(?i)\bHDMI\b|\bDVI\b|\bVGA\b|\bDP\b", token):
        return True
    if re.fullmatch(r"(?i)\d{1,2}G(?:B)?", token):
        return True
    if re.fullmatch(r"(?i)\d{2,3}BIT", token):
        return True
    return False

def _extract_product_model_hint(line: str, aib_hint: str | None) -> str | None:
    head = head_before_brackets(line)
    if not head:
        return None
    text = head
    if aib_hint:
        text = _strip_aib(text)
    text = _strip_chip(text)
    text = _VENDOR_RE.sub(" ", text)
    text = _normalize_model_separators(text)
    text = normalize_spaces(text).strip(" -_/|")
    if not text:
        return None
    tokens = [t for t in text.split(" ") if t]
    cleaned: list[str] = []
    for token in tokens:
        if _is_spec_token(token):
            continue
        cleaned.append(token)
    if not cleaned:
        return None
    if len(cleaned) == 1 and len(cleaned[0]) < 3 and not any(ch.isdigit() for ch in cleaned[0]):
        return None
    return " ".join(cleaned)

def _extract_vram_gb(text: str) -> int | None:
    for pat in (_VRAM_GB_RE, _VRAM_GBD_RE, _VRAM_GD_RE, _VRAM_O_G_RE):
        m = pat.search(text or "")
        if m:
            return int(m.group("gb"))
    return None


def _match_chip(text: str) -> tuple[str | None, str | None]:
    for pat, norm, brand in [
        (_AMD_PRO_RE, _normalize_amd_pro, "AMD"),
        (_RADEON_R79_RE, _normalize_radeon_r79, "AMD"),
        (_RTX_PRO_RE, _normalize_rtx_pro, "NVIDIA"),
        (_RTX_A_RE, _normalize_rtx_a, "NVIDIA"),
        (_RTX_RE, _normalize_rtx, "NVIDIA"),
        (_RX_RE, _normalize_rx, "AMD"),
        (_ARC_RE, _normalize_arc, "Intel"),
        (_GT_RE, _normalize_gt, "NVIDIA"),
        (_N_GT_RE, _normalize_n_gt, "NVIDIA"),
    ]:
        m = pat.search(text or "")
        if m:
            return norm(m), brand
    return None, None

def _extract_chip_from_core_lines(text: str) -> tuple[str | None, str | None]:
    for line in (text or "").splitlines():
        raw = line.strip()
        if not raw:
            continue
        if "繪圖核心" in raw or "GPU核心" in raw or "Graphics" in raw:
            candidate = raw
            for sep in ("：", ":"):
                if sep in candidate:
                    candidate = candidate.split(sep, 1)[-1].strip()
                    break
            sku_hint, brand_hint = _match_chip(candidate)
            if sku_hint:
                return sku_hint, brand_hint
    return None, None

def extract_gpu_hints(title: str) -> tuple[str | None, dict[str, object]]:
    full_text = title or ""
    line = strip_leading_note(first_line(full_text))
    sku_hint, brand_hint = _match_chip(line)
    if not sku_hint:
        sku_hint, brand_hint = _extract_chip_from_core_lines(full_text)

    aib_hint = _extract_aib_hint(line)

    extra = {
        "aib_hint": aib_hint,
        "brand_hint": brand_hint,
        "chip_hint": sku_hint,
        "product_model_hint": _extract_product_model_hint(line, aib_hint),
        "vram_gb_hint": _extract_vram_gb(full_text),
        "is_bundle": False,
        "is_accessory": bool(_ACCESSORY_RE.search(full_text)),
    }
    return sku_hint, extra


def extract_gpu_sku_hint(title: str) -> str | None:
    sku_hint, _extra = extract_gpu_hints(title)
    return sku_hint
