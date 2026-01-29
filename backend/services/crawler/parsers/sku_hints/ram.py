# backend/services/crawler/parsers/sku_hints/ram.py
from __future__ import annotations

import re

from .common import first_line, head_before_brackets, normalize_spaces, strip_leading_note

_BRACKET_CONTENT_RE = re.compile(r"[（(【\[](?P<content>[^）)】\]]+)[）)】\]]") # 抓取括號內的內容
_BRACKET_REMOVE_RE = re.compile(r"[（(【\[][^\)）】\]]*[）)】\]]") # 移除所有括號及其內容
_SKU_TOKEN_RE = re.compile(r"[A-Z0-9][A-Z0-9-]{5,}", flags=re.IGNORECASE) # 至少6字元的可能型號字串
_DDR3L_RE = re.compile(r"DDR3L", flags=re.IGNORECASE) # 特別處理 DDR3L(低電壓版) 為 DDR3
_DDR_RE = re.compile(r"DDR\s*([345])", flags=re.IGNORECASE) # DDR3/DDR4/DDR5
_DDR_SHORT_RE = re.compile(r"D([345])", flags=re.IGNORECASE) # D3/D4/D5 簡寫
_DDR_SPEED_RE = re.compile( # DDR 速度標示，如 DDR4-3200、DDR5 4800 等
    r"(?:DDR3L|DDR[345]|D[345])\s*[- ]?\s*(?P<speed>\d{3,5})(?!\d)",
    flags=re.IGNORECASE,
)
_SPEED_UNIT_RE = re.compile(r"(?P<speed>\d{3,5})\s*(?:MT/s|MHz)(?!\d)", flags=re.IGNORECASE) # 速度單位標示
_CAPACITY_RE = re.compile(r"(?<!\d)(?P<gb>\d{1,3})\s*G(?:B)?(?!\d)", flags=re.IGNORECASE) # 容量標示
_KIT_RE = re.compile( # 套裝標示，如 8GBx2、16GB*4 等
    r"(?P<per>\d{1,3})\s*G(?:B)?\s*[*xX×]\s*(?P<count>\d{1,2})(?!\d)",
    flags=re.IGNORECASE,
)
_CL_RE = re.compile(r"CL\s*(?P<cl>\d{2,3})(?!\d)", flags=re.IGNORECASE) # CAS Latency(等待時間) 標示
_CL_CODE_RE = re.compile(r"C(?P<cl>\d{2,3})(?!\d)", flags=re.IGNORECASE) # CL 代碼標示
_XMP_RE = re.compile(r"\bXMP\b", flags=re.IGNORECASE) # XMP(超頻) 標示
_EXPO_RE = re.compile(r"\bEXPO\b", flags=re.IGNORECASE) # EXPO(超頻) 標示
_RGB_ARGB_RE = re.compile(r"ARGB|RGB", flags=re.IGNORECASE) # RGB 燈效標示
_FORM_FACTOR_RE = re.compile(r"\bSO-?DIMM\b|\bSODIMM\b|\bUDIMM\b|\bRDIMM\b", flags=re.IGNORECASE) # 記憶體形態標示
_ECC_RE = re.compile(r"\bECC\b|\bREGISTERED\b|\bREG\b|\bRDIMM\b", flags=re.IGNORECASE) # ECC 記憶體標示
_ACCESSORY_RE = re.compile( # 記憶體相關配件標示
    r"(記憶體散熱器|記憶體散熱|記憶體風扇|RAM\s*COOLER|MEMORY\s*COOLER|RAM\s*FAN|MEMORY\s*FAN)",
    flags=re.IGNORECASE,
)
_TRAILING_TAG_RE = re.compile(r"\bAI\b\s*$", flags=re.IGNORECASE) # 移除尾端的 AI 標示 
_PLUS_SPLIT_RE = re.compile(r"[+＋]") # 用於分割多組記憶體套裝
_SINGLE_RE = re.compile(r"(單條|單支|單顆)", flags=re.IGNORECASE) # 單條記憶體標示
_NB_RE = re.compile(r"(?<![A-Za-z0-9])NB(?![A-Za-z0-9])|筆電", flags=re.IGNORECASE) # 筆電用記憶體標示
_FIRST_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*") # 抓取第一個連續字元序列

_BUNDLE_KEYWORDS_RE = re.compile(r"(大全配|優惠組合|組合|套餐|搭機|整機)", flags=re.IGNORECASE)
_NON_RAM_PART_RE = re.compile(
    r"(主機板|CPU|處理器|顯卡|SSD|硬碟|HDD|電源|機殼|散熱|水冷|風扇|電源供應器)",
    flags=re.IGNORECASE,
)

def _is_bundle_head(head: str) -> bool:
    h = head or ""
    if not h:
        return False
    # 明確的套裝/組合字眼
    if _BUNDLE_KEYWORDS_RE.search(h):
        return True
    # 有 + 且同時出現非 RAM 零件字眼 → 視為 bundle
    if _PLUS_SPLIT_RE.search(h) and _NON_RAM_PART_RE.search(h):
        return True
    return False

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


def _looks_like_part_number(token: str) -> bool: # 簡單判斷字串是否像是記憶體型號（至少包含兩個英文字母和兩個數字）。
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


def _extract_bracket_sku(text: str) -> str | None: # 從括號內尋找可能的型號字串。
    for m in _BRACKET_CONTENT_RE.finditer(text or ""):
        content = m.group("content") or ""
        for raw in re.split(r"[\s,;/|]+", content):
            token = raw.strip().strip("()[]{}")
            if _looks_like_part_number(token):
                return token
    return None


def _extract_ddr_gen(text: str) -> str | None: # 抽取 DDR 世代資訊，如 DDR3、DDR4、DDR5。
    if _DDR3L_RE.search(text or ""):
        return "DDR3"
    m = _DDR_RE.search(text or "")
    if m:
        return f"DDR{m.group(1)}"
    m = _DDR_SHORT_RE.search(text or "")
    if m:
        return f"DDR{m.group(1)}"
    return None


def _extract_speed(text: str) -> int | None: # 抽取記憶體速度資訊，如 3200、4800 等。
    m = _DDR_SPEED_RE.search(text or "")
    if m:
        return int(m.group("speed"))
    m = _SPEED_UNIT_RE.search(text or "")
    if m:
        return int(m.group("speed"))
    return None


def _extract_capacity(text: str) -> int | None: # 抽取記憶體容量資訊，如 8GB、16GB 等。
    m = _CAPACITY_RE.search(text or "")
    return int(m.group("gb")) if m else None


def _extract_kit(text: str) -> tuple[int | None, int | None]: # 抽取記憶體套裝資訊，如 8GBx2、16GB*4 等，回傳 (每條容量, 條數)。
    m = _KIT_RE.search(text or "")
    if not m:
        return None, None
    per = int(m.group("per"))
    count = int(m.group("count"))
    return per, count


def _extract_cl(text: str) -> int | None: # 抽取 CAS Latency(等待時間) 資訊，如 CL16、C18 等。
    m = _CL_RE.search(text or "")
    if m:
        return int(m.group("cl"))
    m = _CL_CODE_RE.search(text or "")
    return int(m.group("cl")) if m else None


def _extract_rgb(text: str) -> bool | None:  # 抽取 RGB/ARGB 燈效（是否具備）
    return True if _RGB_ARGB_RE.search(text or "") else None


def _extract_form_factor(text: str) -> str | None: # 抽取記憶體形態資訊，如 SO-DIMM、UDIMM、RDIMM 等。
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


def _infer_maker(text: str) -> str | None: # 推測記憶體品牌。
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


def _clean_fallback_title(title: str) -> str: # 清理標題以作為備用的型號提示。
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
    """
    回傳 (sku_hint, extra)：
    maker_hint, ddr_gen_hint, speed_mts_hint, capacity_gb_hint,
    kit_dimms_hint, per_dimm_gb_hint, cl_hint,
    xmp_hint, expo_hint, rgb_hint, form_factor_hint, ecc_hint,
    is_bundle, is_accessory
    """
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
        # 若容量欄位抓到的是「每條容量」（常見於：雙通16G*2 這種沒有總容量前綴的標題）
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


def extract_ram_sku_hint(title: str) -> str | None: # 只回傳 sku_hint(型號提示)，不回傳 extra。
    sku_hint, _extra = extract_ram_hints(title)
    return sku_hint
