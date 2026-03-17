# backend/services/crawler/parsers/sku_hints/core_parts/gpu_chip_specs.py
from __future__ import annotations

import re

_RTX_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])RTX\s*(?P<num>\d{3,4})"
    r"(?:\s*(?P<suffix>TI\s*SUPER|SUPER\s*TI|TI|SUPER))?"
    r"(?=[^A-Za-z0-9]|$)"
)
_RTX_A_RE = re.compile(r"(?i)(?<![A-Za-z0-9])RTX\s*A(?P<num>\d{3,4})(?=[^A-Za-z0-9]|$)")
_RTX_PRO_RE = re.compile(r"(?i)(?<![A-Za-z0-9])RTX\s*PRO\s*(?P<num>\d{4})(?=[^A-Za-z0-9]|$)")
_RX_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])RX\s*(?P<num>\d{4})(?:\s*(?P<suffix>XTX|XT))?"
    r"(?=[^A-Za-z0-9]|$)"
)
_RX_GRE_RE = re.compile(r"(?i)(?<![A-Za-z0-9])RX\s*(?P<num>\d{3,4})\s*GRE(?=[^A-Za-z0-9]|$)")
_ARC_RE = re.compile(r"(?i)(?<![A-Za-z0-9])ARC\s*(?P<series>[AB])\s*(?P<num>\d{3,4})(?=[^A-Za-z0-9]|$)")
_GT_RE = re.compile(r"(?i)(?<![A-Za-z0-9])GT\s*(?P<num>210|710|730|1030)(?=[^A-Za-z0-9]|$)")
_N_GT_RE = re.compile(r"(?i)(?<![A-Za-z0-9])N(?P<num>210|710|730)(?=[^0-9]|$)")
_AMD_PRO_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(?:RADEON\s+)?AI\s+PRO\s+R(?P<num>\d{4})(?=[^A-Za-z0-9]|$)")
_RADEON_R79_RE = re.compile(
    r"(?i)(?<!\d)(?:RADEON\s+)?R(?P<series>[79])\s*(?P<num>\d{3,4})(?P<suffix>X2|X)?(?=[^0-9]|$)"
)


def normalize_gpu_rtx(match: re.Match[str]) -> str:
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


def normalize_gpu_rx(match: re.Match[str]) -> str:
    num = match.group("num")
    suffix = (match.group("suffix") or "").upper()
    parts = ["RX", num]
    if suffix:
        parts.append(suffix)
    return " ".join(parts)


def normalize_gpu_rx_gre(match: re.Match[str]) -> str:
    return f"RX {match.group('num')} GRE"


def normalize_gpu_arc(match: re.Match[str]) -> str:
    return f"ARC {match.group('series').upper()}{match.group('num')}"


def normalize_gpu_gt(match: re.Match[str]) -> str:
    return f"GT {match.group('num')}"


def normalize_gpu_n_gt(match: re.Match[str]) -> str:
    return f"GT {match.group('num')}"


def normalize_gpu_amd_pro(match: re.Match[str]) -> str:
    return f"Radeon AI PRO R{match.group('num')}"


def normalize_gpu_radeon_r79(match: re.Match[str]) -> str:
    chip = f"Radeon R{match.group('series')} {match.group('num')}"
    suffix = (match.group("suffix") or "").upper()
    if suffix:
        chip = f"{chip}{suffix}"
    return chip


def normalize_gpu_rtx_a(match: re.Match[str]) -> str:
    return f"RTX A{match.group('num')}"


def normalize_gpu_rtx_pro(match: re.Match[str]) -> str:
    return f"RTX PRO {match.group('num')}"


def match_gpu_chip(text: str) -> tuple[str | None, str | None]:
    for pat, norm, brand in [
        (_AMD_PRO_RE, normalize_gpu_amd_pro, "AMD"),
        (_RADEON_R79_RE, normalize_gpu_radeon_r79, "AMD"),
        (_RTX_PRO_RE, normalize_gpu_rtx_pro, "NVIDIA"),
        (_RTX_A_RE, normalize_gpu_rtx_a, "NVIDIA"),
        (_RTX_RE, normalize_gpu_rtx, "NVIDIA"),
        (_RX_GRE_RE, normalize_gpu_rx_gre, "AMD"),
        (_RX_RE, normalize_gpu_rx, "AMD"),
        (_ARC_RE, normalize_gpu_arc, "Intel"),
        (_GT_RE, normalize_gpu_gt, "NVIDIA"),
        (_N_GT_RE, normalize_gpu_n_gt, "NVIDIA"),
    ]:
        m = pat.search(text or "")
        if m:
            return norm(m), brand
    return None, None


def strip_gpu_chip_tokens(text: str) -> str:
    out = text
    for pat in (
        _RTX_PRO_RE,
        _RTX_A_RE,
        _RTX_RE,
        _RX_GRE_RE,
        _RX_RE,
        _ARC_RE,
        _GT_RE,
        _AMD_PRO_RE,
        _RADEON_R79_RE,
    ):
        out = pat.sub(" ", out)
    return out


def extract_gpu_chip_and_brand(line: str, full_text: str) -> tuple[str | None, str | None]:
    sku_hint, brand_hint = match_gpu_chip(line)
    if sku_hint:
        return sku_hint, brand_hint

    for raw in (full_text or "").splitlines():
        line_text = raw.strip()
        if not line_text:
            continue
        if "繪圖核心" in line_text or "GPU核心" in line_text or "Graphics" in line_text:
            candidate = line_text
            for sep in ("：", ":"):
                if sep in candidate:
                    candidate = candidate.split(sep, 1)[-1].strip()
                    break
            sku_hint, brand_hint = match_gpu_chip(candidate)
            if sku_hint:
                return sku_hint, brand_hint

    return None, None
