from __future__ import annotations

import re

from ..common import head_before_brackets, normalize_spaces
from ..shared_specs import normalized_title_line

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
_VRAM_GB_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(?P<gb>\d{1,2})\s*G(?:B)?(?=[^A-Za-z0-9]|$)")
_VRAM_GBD_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(?P<gb>\d{1,2})\s*GBD\d(?=[^A-Za-z0-9]|$)")
_VRAM_GD_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(?P<gb>\d{1,2})\s*GD\d(?=[^A-Za-z0-9]|$)")
_VRAM_O_G_RE = re.compile(r"(?i)(?<![A-Za-z0-9])O(?P<gb>\d{1,2})G(?=[^A-Za-z0-9]|$)")
_ACCESSORY_RE = re.compile(
    r"(?i)(支撐架|支架|支撐|顯示卡支架|GPU\s*holder|holder|bracket|Herculx|"
    r"轉接線|轉接頭|轉接器|轉接|轉換線|延長線|線材)"
)
_PLUS_SPLIT_RE = re.compile(r"[+＋]")
_BUNDLE_KEYWORDS_RE = re.compile(r"(?i)(大全配|套裝|組合|優惠組合|優惠組|套件|組|combo|bundle)")
_OTHER_PARTS_RE = re.compile(
    r"(?i)(CPU|處理器|主機板|MB|RAM|記憶體|SSD|HDD|硬碟|電源|PSU|機殼|散熱|水冷|螢幕|鍵盤|滑鼠)"
)
_SPEC_PLUS_RE = re.compile(
    r"(?i)(HDMI|DP|DVI|VGA|USB|TYPE-?C|PCI-?E|GDDR\d|DDR\d|\d{1,2}PIN|\d{1,2}BIT)"
    r"\s*[+＋]\s*"
    r"(HDMI|DP|DVI|VGA|USB|TYPE-?C|PCI-?E|GDDR\d|DDR\d|\d{1,2}PIN|\d{1,2}BIT)"
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
_BRACKET_MODEL_RE = re.compile(r"[（(【]\s*(?P<code>[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)\s*[）)】]")
_CHIP_REMOVE_PATTERNS: list[re.Pattern[str]] = [
    _RTX_PRO_RE,
    _RTX_A_RE,
    _RTX_RE,
    _RX_GRE_RE,
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


def _normalize_rx_gre(match: re.Match[str]) -> str:
    return f"RX {match.group('num')} GRE"


def _normalize_arc(match: re.Match[str]) -> str:
    return f"ARC {match.group('series').upper()}{match.group('num')}"


def _normalize_gt(match: re.Match[str]) -> str:
    return f"GT {match.group('num')}"


def _normalize_n_gt(match: re.Match[str]) -> str:
    return f"GT {match.group('num')}"


def _normalize_amd_pro(match: re.Match[str]) -> str:
    return f"Radeon AI PRO R{match.group('num')}"


def _normalize_radeon_r79(match: re.Match[str]) -> str:
    chip = f"Radeon R{match.group('series')} {match.group('num')}"
    suffix = (match.group("suffix") or "").upper()
    if suffix:
        chip = f"{chip}{suffix}"
    return chip


def _normalize_rtx_a(match: re.Match[str]) -> str:
    return f"RTX A{match.group('num')}"


def _normalize_rtx_pro(match: re.Match[str]) -> str:
    return f"RTX PRO {match.group('num')}"


def extract_gpu_aib_hint(text: str) -> str | None:
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


def _extract_bracket_model_hint(text: str) -> str | None:
    for m in _BRACKET_MODEL_RE.finditer(text or ""):
        code = m.group("code")
        if len(code) < 5:
            continue
        if not re.search(r"[A-Za-z]", code) or not re.search(r"\d", code):
            continue
        if len(re.findall(r"\d", code)) < 2:
            continue
        return code
    return None


def extract_gpu_product_model_hint(line: str, aib_hint: str | None) -> str | None:
    head = head_before_brackets(line)
    hint = None
    if head:
        text = head
        if aib_hint:
            text = _strip_aib(text)
        text = _strip_chip(text)
        text = _VENDOR_RE.sub(" ", text)
        text = _normalize_model_separators(text)
        text = normalize_spaces(text).strip(" -_/|")
        if text:
            cleaned = [token for token in text.split(" ") if token and not _is_spec_token(token)]
            if cleaned:
                if not (
                    len(cleaned) == 1
                    and len(cleaned[0]) < 3
                    and not any(ch.isdigit() for ch in cleaned[0])
                ):
                    hint = " ".join(cleaned)
    if hint is None:
        return _extract_bracket_model_hint(line)
    return hint


def extract_gpu_vram_gb(text: str) -> int | None:
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
        (_RX_GRE_RE, _normalize_rx_gre, "AMD"),
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


def extract_gpu_chip_and_brand(line: str, full_text: str) -> tuple[str | None, str | None]:
    sku_hint, brand_hint = _match_chip(line)
    if sku_hint:
        return sku_hint, brand_hint
    return _extract_chip_from_core_lines(full_text)


def infer_gpu_bundle(title: str) -> bool:
    text = title or ""
    line = normalized_title_line(text)
    head = head_before_brackets(line) or line
    if _BUNDLE_KEYWORDS_RE.search(text):
        return True
    if not _PLUS_SPLIT_RE.search(head):
        return False
    if _SPEC_PLUS_RE.search(head):
        return False
    parts = [p.strip() for p in _PLUS_SPLIT_RE.split(head) if p.strip()]
    return any(_OTHER_PARTS_RE.search(p) for p in parts[1:])


def infer_gpu_accessory(text: str) -> bool:
    return bool(_ACCESSORY_RE.search(text or ""))
