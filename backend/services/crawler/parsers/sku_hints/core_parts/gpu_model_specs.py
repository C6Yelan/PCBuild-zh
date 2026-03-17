# backend/services/crawler/parsers/sku_hints/core_parts/gpu_model_specs.py
from __future__ import annotations

import re

from ..common import head_before_brackets, normalize_spaces
from ..shared_specs import normalized_title_line
from .gpu_chip_specs import strip_gpu_chip_tokens

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


def extract_gpu_aib_hint(text: str) -> str | None:
    for pat, norm in _AIB_PATTERNS:
        if pat.search(text or ""):
            return norm
    return None


def strip_gpu_aib_tokens(text: str) -> str:
    out = text
    for pat, _norm in _AIB_PATTERNS:
        out = pat.sub(" ", out)
    return out


def normalize_gpu_model_separators(text: str) -> str:
    if not text:
        return text
    text = re.sub(r"\s*-\s*-\s*", "-", text)
    text = re.sub(r"-{2,}", "-", text)
    return text


def is_gpu_spec_token(token: str) -> bool:
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


def extract_gpu_bracket_model_hint(text: str) -> str | None:
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
            text = strip_gpu_aib_tokens(text)
        text = strip_gpu_chip_tokens(text)
        text = _VENDOR_RE.sub(" ", text)
        text = normalize_gpu_model_separators(text)
        text = normalize_spaces(text).strip(" -_/|")
        if text:
            cleaned = [token for token in text.split(" ") if token and not is_gpu_spec_token(token)]
            if cleaned:
                if not (
                    len(cleaned) == 1
                    and len(cleaned[0]) < 3
                    and not any(ch.isdigit() for ch in cleaned[0])
                ):
                    hint = " ".join(cleaned)
    if hint is None:
        return extract_gpu_bracket_model_hint(line)
    return hint


def extract_gpu_vram_gb(text: str) -> int | None:
    for pat in (_VRAM_GB_RE, _VRAM_GBD_RE, _VRAM_GD_RE, _VRAM_O_G_RE):
        m = pat.search(text or "")
        if m:
            return int(m.group("gb"))
    return None


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
