# backend/services/crawler/parsers/sku_hints/ssd.py
from __future__ import annotations

import re

from .common import first_line, head_before_brackets, normalize_spaces, strip_leading_note

_BRACKET_CONTENT_RE = re.compile(r"[（(【\[](?P<content>[^）)】\]]+)[）)】\]]") # 提取括號內的內容
_BRACKET_REMOVE_RE = re.compile(r"[（(【\[][^\)）】\]]*[）)】\]]") # 用於清除括號及其內容
_SKU_TOKEN_RE = re.compile(r"[A-Z0-9][A-Z0-9-]{4,}", flags=re.IGNORECASE) # 用於尋找可能的型號字串
_PLUS_SPLIT_RE = re.compile(r"[+＋]") # 用於在 '+' 號處切割字串

_CAPACITY_RE = re.compile( # 提取容量數值及單位
    r"(?i)(?<!\d)(?P<num>\d+(?:\.\d+)?)\s*(?P<unit>TB|T|GB|G)(?![A-Za-z0-9])"
)
_FORM_25_RE = re.compile(r"2\.5吋|2\.5\"", flags=re.IGNORECASE) # 用於識別 2.5 吋規格
_M2_RE = re.compile(r"\bM\.2\b", flags=re.IGNORECASE) # 用於識別 M.2 規格
_M2_LEN_RE = re.compile(r"\b(22(?:30|42|60|80|110))\b") # 提取 M.2 長度規格
_PCIE_GEN_RE = re.compile(r"(?i)\bGEN\s*(?P<gen>[345])\b") # 提取 PCIe 世代資訊
_PCIE_VER_RE = re.compile(r"(?i)PCI-?E\s*(?P<gen>[345])(?:\.0)?") # 提取 PCIe 版本資訊
_PCIE_RE = re.compile(r"(?i)\bPCI-?E\b") # 用於識別 PCIe 規格
_NVME_RE = re.compile(r"(?i)\bNVME\b") # 用於識別 NVMe 規格
_SATA_RE = re.compile(r"(?i)\bSATA\b") # 用於識別 SATA 規格
_AHCI_RE = re.compile(r"(?i)\bAHCI\b") # 用於識別 AHCI 規格
_READ_RE = re.compile(r"(?i)(?:讀|read)[^0-9]{0,4}(?P<val>\d{3,5})(?:\s*(?:M|MB/s))?") # 提取讀取速度
_WRITE_RE = re.compile(r"(?i)(?:寫|write)[^0-9]{0,4}(?P<val>\d{3,5})(?:\s*(?:M|MB/s))?") # 提取寫入速度

_NAND_RE = re.compile(r"(?i)(3D\s*NAND|TLC|QLC)") # 用於識別 NAND 類型
_DRAM_RE = re.compile(r"(?i)\bDRAM\b|快取") # 用於識別 DRAM 或快取
_CONTROLLER_LABEL_RE = re.compile( # 提取控制器型號
    r"(?i)(?:主控|controller)\s*[:：]?\s*(?P<model>[A-Za-z0-9-]{3,})"
)
_CONTROLLER_MODEL_RE = re.compile(r"\b(?P<model>(?:SMI?|PS|IG|MAP|RTS|E)\d{2,4})\b") # 提取控制器型號的備用模式
_HEATSINK_RE = re.compile(r"(散熱|散熱片|石墨烯)") # 用於識別散熱相關字樣
_SINGLE_SIDED_RE = re.compile(r"單面") # 用於識別單面
_LIMIT_RE = re.compile(r"(限購|限組裝)") # 用於識別限購或限組裝
_WARRANTY_RE = re.compile(r"[【\[]?(?P<val>[一二三四五六七八九十\d]+)年(?:保)?[】\]]?") # 提取保固年限

_SPEC_TOKEN_RE = re.compile( # 用於排除非型號的規格字串
    r"(?i)^(?:\d{3,4}G(?:B)?|\d+(?:\.\d+)?T(?:B)?|GEN[345]|PCI-?E|NVME|SATA|M\.2)$"
)

_BRAND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:\bACER\b|宏碁)", flags=re.IGNORECASE), "ACER"),
    (re.compile(r"(?:\bSAMSUNG\b|三星)", flags=re.IGNORECASE), "SAMSUNG"),
    (re.compile(r"(?:\bKINGSTON\b|金士頓)", flags=re.IGNORECASE), "KINGSTON"),
    (re.compile(r"(?:\bCRUCIAL\b|美光)", flags=re.IGNORECASE), "CRUCIAL"),
    (re.compile(r"(?:\bADATA\b|威剛)", flags=re.IGNORECASE), "ADATA"),
    (re.compile(r"(?:\bKIOXIA\b|鎧俠|東芝)", flags=re.IGNORECASE), "KIOXIA"),
    (re.compile(r"(?:\bWD\b|WESTERN\s*DIGITAL|威騰)", flags=re.IGNORECASE), "WD"),
    (re.compile(r"(?:\bSEAGATE\b|希捷)", flags=re.IGNORECASE), "SEAGATE"),
    (re.compile(r"(?i)\bCORSAIR\b|海盜船"), "CORSAIR"),
    (re.compile(r"(?i)\bMSI\b|微星"), "MSI"),
    (re.compile(r"(?i)\bTEAMGROUP\b|\bTEAM\s*GROUP\b|\bT-?FORCE\b|十銓"), "TEAMGROUP"),
    (re.compile(r"(?i)\bZHITAI\b|致鈦|致態|致态"), "ZHITAI"),
]


def _looks_like_model(token: str) -> bool: # 判斷字串是否看起來像是型號（包含字母和數字，且非規格字串）。
    if not token or len(token) < 5:
        return False
    if _SPEC_TOKEN_RE.match(token):
        return False
    has_alpha = any(ch.isalpha() for ch in token)
    has_digit = any(ch.isdigit() for ch in token)
    return has_alpha and has_digit


def _extract_bracket_model(text: str) -> str | None: # 從括號內提取可能的型號提示。
    for m in _BRACKET_CONTENT_RE.finditer(text or ""):
        content = m.group("content") or ""
        for raw in re.split(r"[\s,;/|]+", content):
            token = raw.strip().strip("()[]{}")
            if _looks_like_model(token):
                return token
    return None


def _infer_brand(text: str) -> str | None: # 推斷品牌提示。
    if not text:
        return None
    for pat, norm in _BRAND_PATTERNS:
        if pat.search(text):
            return norm
    m = re.match(r"[A-Za-z][A-Za-z0-9-]*", text.strip())
    if m:
        return m.group(0).upper()
    return None


def _clean_model(text: str, brand_hint: str | None) -> str | None: # 清理並提取型號提示，去除品牌及多餘資訊。
    line = normalize_spaces(strip_leading_note(first_line(text)))
    base = head_before_brackets(line) or line
    base = _BRACKET_REMOVE_RE.sub(" ", base)
    base = _PLUS_SPLIT_RE.split(base, 1)[0].strip()
    if brand_hint:
        base = re.sub(re.escape(brand_hint), " ", base, flags=re.IGNORECASE)
    base = normalize_spaces(base).strip(" -_/|")
    return base or None


def _extract_capacity_gib(text: str) -> int | None: # 提取容量並轉換為 GiB。
    m = _CAPACITY_RE.search(text or "")
    if not m:
        return None
    num = float(m.group("num"))
    unit = m.group("unit").upper()
    if unit in ("T", "TB"):
        bytes_val = num * 10**12
    else:
        bytes_val = num * 10**9
    return int(round(bytes_val / (1 << 30)))


def _extract_pcie_gen(text: str) -> int | None: # 提取 PCIe 世代資訊。
    m = _PCIE_GEN_RE.search(text or "")
    if not m:
        m = _PCIE_VER_RE.search(text or "")
    if not m:
        return None
    return int(m.group("gen"))


def _extract_seq_speed(text: str, pat: re.Pattern[str]) -> int | None: # 提取連續讀寫速度。
    m = pat.search(text or "")
    if not m:
        return None
    return int(m.group("val"))

def _extract_write_after_read(text: str) -> int | None:
    """
    Fallback: handle patterns like:
      - 讀7100/6100
      - 讀7300/:6800
    Only used when explicit '寫/write' is not found.
    """
    m = _READ_RE.search(text or "")
    if not m:
        return None

    tail = (text or "")[m.end():]
    m2 = re.search(r"[:/][^0-9]{0,4}(?P<val>\d{3,5})(?!\d)", tail)
    if not m2:
        return None
    return int(m2.group("val"))



def _extract_controller(text: str) -> str | None: # 提取控制器型號提示。
    m = _CONTROLLER_LABEL_RE.search(text or "")
    if m:
        return m.group("model").upper()
    m = _CONTROLLER_MODEL_RE.search(text or "")
    if m:
        return m.group("model").upper()
    return None


_CHINESE_NUM = { # 中文數字對應的整數值
    "一": 1,
    "二": 2,
    "三": 3,
    "四": 4,
    "五": 5,
    "六": 6,
    "七": 7,
    "八": 8,
    "九": 9,
    "十": 10,
}


def _parse_warranty_years(text: str) -> int | None: # 解析保固年限，支援中文及數字。
    m = _WARRANTY_RE.search(text or "")
    if not m:
        return None
    raw = m.group("val")
    if raw.isdigit():
        return int(raw)
    if raw in _CHINESE_NUM:
        return _CHINESE_NUM[raw]
    if raw.startswith("十") and len(raw) == 2 and raw[1] in _CHINESE_NUM:
        return 10 + _CHINESE_NUM[raw[1]]
    if len(raw) == 2 and raw[0] in _CHINESE_NUM and raw[1] == "十":
        return _CHINESE_NUM[raw[0]] * 10
    return None


def extract_ssd_sku_hint(title: str) -> str | None: # 回傳 SSD 型號提示（sku_hint）。
    line = normalize_spaces(strip_leading_note(first_line(title)))
    hint = _extract_bracket_model(line)
    if hint:
        return hint
    for m in _SKU_TOKEN_RE.finditer(line or ""):
        token = m.group(0)
        if _looks_like_model(token):
            return token
    return _clean_model(line, None)


def extract_ssd_hints(title: str) -> tuple[str | None, dict[str, object]]:
    """
    回傳 (sku_hint, extra)：
    brand_hint, model_hint, capacity_gib, form_factor_hint, m2_length_hint,
    interface_hint, pcie_gen_hint, protocol_hint, seq_read_mb_s, seq_write_mb_s,
    nand_hint, dram_cache_hint, controller_hint, has_heatsink_hint,
    single_sided_hint, warranty_years, limit_hint
    """
    text = title or ""
    line = normalize_spaces(strip_leading_note(first_line(text)))
    head = head_before_brackets(line)

    brand_hint = _infer_brand(head or line)
    sku_hint = extract_ssd_sku_hint(line)
    model_hint = _clean_model(line, brand_hint)

    capacity_gib = _extract_capacity_gib(head) or _extract_capacity_gib(line)

    form_factor_hint = None
    if _FORM_25_RE.search(line):
        form_factor_hint = '2.5"'
    elif _M2_RE.search(line):
        form_factor_hint = "M.2"

    m2_length_hint = None
    if form_factor_hint == "M.2":
        m2_len = _M2_LEN_RE.search(line or "")
        if m2_len:
            m2_length_hint = int(m2_len.group(1))

    interface_hint = None
    protocol_hint = None
    if _NVME_RE.search(line):
        interface_hint = "PCIe"
        protocol_hint = "NVMe"
    elif _SATA_RE.search(line):
        interface_hint = "SATA"
        protocol_hint = "AHCI"
    elif _PCIE_RE.search(line) or _PCIE_GEN_RE.search(line) or _PCIE_VER_RE.search(line):
        interface_hint = "PCIe"

    # Fallback: CoolPC SSD 類別下，2.5" 且未明示介面時，合理推定為 SATA/AHCI
    if form_factor_hint == '2.5"' and interface_hint is None:
        interface_hint = "SATA"
        protocol_hint = "AHCI"

    # PCIe SSD 幾乎皆為 NVMe 協定（標題常不明寫 NVMe）
    if interface_hint == "PCIe" and protocol_hint is None:
        protocol_hint = "NVMe"

    # 標題若未明寫 M.2，但已判定 PCIe（且非 2.5"），在 IGrp=7 語境下可推為 M.2
    if interface_hint == "PCIe" and form_factor_hint is None:
        form_factor_hint = "M.2"

    pcie_gen_hint = _extract_pcie_gen(line)
    seq_read_mb_s = _extract_seq_speed(line, _READ_RE)
    seq_write_mb_s = _extract_seq_speed(line, _WRITE_RE)
    if seq_write_mb_s is None:
        seq_write_mb_s = _extract_write_after_read(line)

    nand_hint = None
    nand_m = _NAND_RE.search(line)
    if nand_m:
        nand_hint = nand_m.group(1).upper().replace(" ", "")
        if nand_hint == "3DNAND":
            nand_hint = "3D NAND"

    dram_cache_hint = True if _DRAM_RE.search(line) else None
    controller_hint = _extract_controller(line)
    has_heatsink_hint = True if _HEATSINK_RE.search(line) else None
    single_sided_hint = True if _SINGLE_SIDED_RE.search(line) else None
    warranty_years = _parse_warranty_years(line)

    limit_hint = None
    limit_m = _LIMIT_RE.search(line)
    if limit_m:
        limit_hint = limit_m.group(1)

    extra = {
        "brand_hint": brand_hint, # 品牌提示
        "model_hint": model_hint, # 型號提示
        "capacity_gib": capacity_gib, # 容量提示（GiB）
        "form_factor_hint": form_factor_hint, # 規格提示（2.5"、M.2）
        "m2_length_hint": m2_length_hint, # M.2 長度提示
        "interface_hint": interface_hint, # 介面提示（SATA、PCIe）
        "pcie_gen_hint": pcie_gen_hint, # PCIe 世代提示(3、4、5)
        "protocol_hint": protocol_hint, # 協議提示（AHCI、NVMe）
        "seq_read_mb_s": seq_read_mb_s, # 連續讀取速度提示（MB/s）
        "seq_write_mb_s": seq_write_mb_s, # 連續寫入速度提示（MB/s）
        "nand_hint": nand_hint, # NAND 類型提示（TLC、QLC、3D NAND）
        "dram_cache_hint": dram_cache_hint, # DRAM 快取提示(有/無)
        "controller_hint": controller_hint, # 控制器提示(型號)
        "has_heatsink_hint": has_heatsink_hint, # 是否有散熱片提示
        "single_sided_hint": single_sided_hint, # 是否單面提示
        "warranty_years": warranty_years, # 保固年限提示
        "limit_hint": limit_hint, # 限購/限組裝提示
    }
    extra = {k: v for k, v in extra.items() if v is not None}
    return sku_hint, extra
