# backend/services/crawler/parsers/sku_hints/gpu.py
from __future__ import annotations

import re

from ..common import first_line, head_before_brackets, normalize_spaces, strip_leading_note

_RTX_RE = re.compile( # NVIDIA RTX 系列型號格式
    r"(?i)(?<![A-Za-z0-9])RTX\s*(?P<num>\d{3,4})"
    r"(?:\s*(?P<suffix>TI\s*SUPER|SUPER\s*TI|TI|SUPER))?"
    r"(?=[^A-Za-z0-9]|$)"
)
_RTX_A_RE = re.compile( # NVIDIA RTX A (繪圖卡)系列型號格式
    r"(?i)(?<![A-Za-z0-9])RTX\s*A(?P<num>\d{3,4})(?=[^A-Za-z0-9]|$)"
)
_RTX_PRO_RE = re.compile( # NVIDIA RTX PRO (專業領域)系列型號格式
    r"(?i)(?<![A-Za-z0-9])RTX\s*PRO\s*(?P<num>\d{4})(?=[^A-Za-z0-9]|$)"
)
_RX_RE = re.compile( # AMD RX 系列型號格式
    r"(?i)(?<![A-Za-z0-9])RX\s*(?P<num>\d{4})(?:\s*(?P<suffix>XTX|XT))?"
    r"(?=[^A-Za-z0-9]|$)"
)
_RX_GRE_RE = re.compile( # AMD RX GRE 系列型號格式
    r"(?i)(?<![A-Za-z0-9])RX\s*(?P<num>\d{3,4})\s*GRE(?=[^A-Za-z0-9]|$)"
)
_ARC_RE = re.compile( # Intel ARC 系列型號格式
    r"(?i)(?<![A-Za-z0-9])ARC\s*(?P<series>[AB])\s*(?P<num>\d{3,4})(?=[^A-Za-z0-9]|$)"
)
_GT_RE = re.compile( # NVIDIA GT 系列型號格式
    r"(?i)(?<![A-Za-z0-9])GT\s*(?P<num>210|710|730|1030)(?=[^A-Za-z0-9]|$)"
)
_N_GT_RE = re.compile( # NVIDIA N 系列型號格式 (老卡)
    r"(?i)(?<![A-Za-z0-9])N(?P<num>210|710|730)(?=[^0-9]|$)"
)
_AMD_PRO_RE = re.compile( # AMD Radeon AI PRO 系列型號格式
    r"(?i)(?<![A-Za-z0-9])(?:RADEON\s+)?AI\s+PRO\s+R(?P<num>\d{4})(?=[^A-Za-z0-9]|$)"
)
_RADEON_R79_RE = re.compile( # AMD Radeon R7/R9 系列型號格式
    r"(?i)(?<!\d)(?:RADEON\s+)?R(?P<series>[79])\s*(?P<num>\d{3,4})(?P<suffix>X2|X)?(?=[^0-9]|$)"
)
_VRAM_GB_RE = re.compile(  # 顯示記憶體容量格式：如 4G、8GB
    r"(?i)(?<![A-Za-z0-9])(?P<gb>\d{1,2})\s*G(?:B)?(?=[^A-Za-z0-9]|$)"
)
_VRAM_GBD_RE = re.compile( # 顯示記憶體容量格式：如 4GBD5、8GBD6
    r"(?i)(?<![A-Za-z0-9])(?P<gb>\d{1,2})\s*GBD\d(?=[^A-Za-z0-9]|$)"
)
_VRAM_GD_RE = re.compile( # 顯示記憶體容量格式：如 4GD5、8GD6
    r"(?i)(?<![A-Za-z0-9])(?P<gb>\d{1,2})\s*GD\d(?=[^A-Za-z0-9]|$)"
)
_VRAM_O_G_RE = re.compile( # 顯示記憶體容量格式：如 O4G、O8G
    r"(?i)(?<![A-Za-z0-9])O(?P<gb>\d{1,2})G(?=[^A-Za-z0-9]|$)"
)
_ACCESSORY_RE = re.compile( # 顯卡配件關鍵字
    r"(?i)(支撐架|支架|支撐|顯示卡支架|GPU\s*holder|holder|bracket|Herculx|"
    r"轉接線|轉接頭|轉接器|轉接|轉換線|延長線|線材)"
)
_PLUS_SPLIT_RE = re.compile(r"[+＋]")

_BUNDLE_KEYWORDS_RE = re.compile(
    r"(?i)(大全配|套裝|組合|優惠組合|優惠組|套件|組|combo|bundle)"
)
# 只要 + 的另一側出現這些「非顯卡本體」字樣，就視為 bundle
_OTHER_PARTS_RE = re.compile(
    r"(?i)(CPU|處理器|主機板|MB|RAM|記憶體|SSD|HDD|硬碟|電源|PSU|機殼|散熱|水冷|螢幕|鍵盤|滑鼠)"
)
# 排除「規格串接」類的 +，例如 HDMI+DP、8+6pin 等
_SPEC_PLUS_RE = re.compile(
    r"(?i)(HDMI|DP|DVI|VGA|USB|TYPE-?C|PCI-?E|GDDR\d|DDR\d|\d{1,2}PIN|\d{1,2}BIT)"
    r"\s*[+＋]\s*"
    r"(HDMI|DP|DVI|VGA|USB|TYPE-?C|PCI-?E|GDDR\d|DDR\d|\d{1,2}PIN|\d{1,2}BIT)"
)
_AIB_PATTERNS: list[tuple[re.Pattern[str], str]] = [ # 常見 AIB 廠商名稱及其正規化形式
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
_VENDOR_RE = re.compile(r"(?i)\b(NVIDIA|AMD|RADEON|INTEL|GEFORCE)\b") # 廠商品牌關鍵字
_SPEC_TOKEN_RE = re.compile( # 規格相關的 token，不應納入型號提示
    r"(?i)^(?:\d{1,2}G(?:B)?|\d{2,3}BIT|GDDR\d|DDR\d|HDMI|DVI|VGA|DP|"
    r"DISPLAYPORT|LOW|PROFILE|LP|PCI-?E\d?|BLACKWELL|MAX-?Q)$"
)
_BRACKET_MODEL_RE = re.compile( # 括號內的型號提示，如 (3060-Ti)、【RX6800XT】等
    r"[（(【]\s*(?P<code>[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)\s*[）)】]"
)
_CHIP_REMOVE_PATTERNS: list[re.Pattern[str]] = [ # 用來移除型號中的晶片相關字串
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


def _normalize_rtx(match: re.Match[str]) -> str: # 正規化 NVIDIA RTX 型號格式
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


def _normalize_rx(match: re.Match[str]) -> str: # 正規化 AMD RX 型號格式
    num = match.group("num")
    suffix = (match.group("suffix") or "").upper()
    parts = ["RX", num]
    if suffix:
        parts.append(suffix)
    return " ".join(parts)

def _normalize_rx_gre(match: re.Match[str]) -> str: # 正規化 AMD RX GRE 型號格式
    num = match.group("num")
    return f"RX {num} GRE"


def _normalize_arc(match: re.Match[str]) -> str: # 正規化 Intel ARC 型號格式
    series = match.group("series").upper()
    num = match.group("num")
    return f"ARC {series}{num}"

def _normalize_gt(match: re.Match[str]) -> str: # 正規化 NVIDIA GT 型號格式
    num = match.group("num")
    return f"GT {num}"

def _normalize_n_gt(match: re.Match[str]) -> str: # 正規化 NVIDIA N 系列 GT 型號格式 (老卡)
    num = match.group("num")
    return f"GT {num}"

def _normalize_amd_pro(match: re.Match[str]) -> str: # 正規化 AMD PRO 型號格式
    num = match.group("num")
    return f"Radeon AI PRO R{num}"

def _normalize_radeon_r79(match: re.Match[str]) -> str: # 正規化 Radeon R79 系列型號格式
    series = match.group("series")
    num = match.group("num")
    suffix = (match.group("suffix") or "").upper()
    chip = f"Radeon R{series} {num}"
    if suffix:
        chip = f"{chip}{suffix}"
    return chip

def _normalize_rtx_a(match: re.Match[str]) -> str: # 正規化 NVIDIA RTX A (繪圖卡) 型號格式
    num = match.group("num")
    return f"RTX A{num}"

def _normalize_rtx_pro(match: re.Match[str]) -> str: # 正規化 NVIDIA RTX PRO (專業領域) 型號格式
    num = match.group("num")
    return f"RTX PRO {num}"

def _extract_aib_hint(text: str) -> str | None: # 抽取 AIB 廠商提示
    for pat, norm in _AIB_PATTERNS:
        if pat.search(text or ""):
            return norm
    return None

def _strip_aib(text: str) -> str: # 移除型號中的 AIB 廠商名稱
    for pat, _norm in _AIB_PATTERNS:
        text = pat.sub(" ", text)
    return text

def _strip_chip(text: str) -> str: # 移除型號中的晶片相關字串
    for pat in _CHIP_REMOVE_PATTERNS:
        text = pat.sub(" ", text)
    return text

def _normalize_model_separators(text: str) -> str: # 正規化型號中的分隔符號
    if not text:
        return text
    text = re.sub(r"\s*-\s*-\s*", "-", text)
    text = re.sub(r"-{2,}", "-", text)
    return text

def _is_spec_token(token: str) -> bool: # 判斷是否為規格相關的 token
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

def _extract_bracket_model_hint(text: str) -> str | None: # 抽取括號中的型號提示 
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

def _extract_product_model_hint(line: str, aib_hint: str | None) -> str | None: # 抽取產品型號提示
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
            tokens = [t for t in text.split(" ") if t]
            cleaned: list[str] = []
            for token in tokens:
                if _is_spec_token(token):
                    continue
                cleaned.append(token)
            if cleaned:
                if not (
                    len(cleaned) == 1
                    and len(cleaned[0]) < 3
                    and not any(ch.isdigit() for ch in cleaned[0])
                ):
                    hint = " ".join(cleaned)
    if hint is None:
        bracket_hint = _extract_bracket_model_hint(line)
        if bracket_hint:
            return bracket_hint
    return hint

def _extract_vram_gb(text: str) -> int | None: # 抽取顯示記憶體容量（GB）
    for pat in (_VRAM_GB_RE, _VRAM_GBD_RE, _VRAM_GD_RE, _VRAM_O_G_RE):
        m = pat.search(text or "")
        if m:
            return int(m.group("gb"))
    return None


def _match_chip(text: str) -> tuple[str | None, str | None]: # 匹配並正規化 GPU 晶片型號，回傳型號及品牌提示
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

def _extract_chip_from_core_lines(text: str) -> tuple[str | None, str | None]: # 從多行文字中抽取 GPU 晶片型號提示
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

def _infer_is_bundle(title: str) -> bool:
    text = title or ""
    line = strip_leading_note(first_line(text))
    head = head_before_brackets(line) or line

    if _BUNDLE_KEYWORDS_RE.search(text):
        return True

    if not _PLUS_SPLIT_RE.search(head):
        return False

    # 例如 HDMI+DP 這種規格串接：直接排除
    if _SPEC_PLUS_RE.search(head):
        return False

    parts = [p.strip() for p in _PLUS_SPLIT_RE.split(head) if p.strip()]
    # 若 + 後面出現其他零件關鍵字 -> bundle
    return any(_OTHER_PARTS_RE.search(p) for p in parts[1:])

def extract_gpu_hints(title: str) -> tuple[str | None, dict[str, object]]: # 從標題中抽取 GPU 型號提示及其他額外資訊
    full_text = title or ""
    line = strip_leading_note(first_line(full_text))
    sku_hint, brand_hint = _match_chip(line)
    if not sku_hint:
        sku_hint, brand_hint = _extract_chip_from_core_lines(full_text)

    aib_hint = _extract_aib_hint(line)

    extra = {
        "aib_hint": aib_hint, # 板廠商（ASUS/MSI/GIGABYTE…）提示
        "brand_hint": brand_hint, # 廠商提示（NVIDIA/AMD/Intel）
        "chip_hint": sku_hint, # GPU 核心提示
        "product_model_hint": _extract_product_model_hint(line, aib_hint), # 產品型號提示
        "vram_gb_hint": _extract_vram_gb(full_text), # 顯示記憶體容量提示
        "is_bundle": _infer_is_bundle(full_text), # 是否為套裝
        "is_accessory": bool(_ACCESSORY_RE.search(full_text)), # 是否為 GPU 配件
    }
    return sku_hint, extra


def extract_gpu_sku_hint(title: str) -> str | None: # 從標題中抽取 GPU 型號提示，只取核心
    sku_hint, _extra = extract_gpu_hints(title)
    return sku_hint
