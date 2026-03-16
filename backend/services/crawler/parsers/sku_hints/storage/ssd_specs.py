from __future__ import annotations

import re

from ..common import first_line, head_before_brackets, normalize_spaces, strip_leading_note
from ..shared_specs import extract_capacity_gib
from ..shared_specs import normalized_title_line

_BRACKET_CONTENT_RE = re.compile(r"[（(【\[](?P<content>[^）)】\]]+)[）)】\]]")
_BRACKET_REMOVE_RE = re.compile(r"[（(【\[][^\)）】\]]*[）)】\]]")
_SKU_TOKEN_RE = re.compile(r"[A-Z0-9][A-Z0-9-]{4,}", flags=re.IGNORECASE)
_PLUS_SPLIT_RE = re.compile(r"[+＋]")

_FORM_25_RE = re.compile(r"2\.5吋|2\.5\"", flags=re.IGNORECASE)
_M2_RE = re.compile(r"\bM\.2\b", flags=re.IGNORECASE)
_M2_LEN_RE = re.compile(r"\b(22(?:30|42|60|80|110))\b")
_PCIE_GEN_RE = re.compile(r"(?i)\bGEN\s*(?P<gen>[345])\b")
_PCIE_VER_RE = re.compile(r"(?i)PCI-?E\s*(?P<gen>[345])(?:\.0)?")
_PCIE_RE = re.compile(r"(?i)\bPCI-?E\b")
_NVME_RE = re.compile(r"(?i)\bNVME\b")
_SATA_RE = re.compile(r"(?i)\bSATA\b")
_AHCI_RE = re.compile(r"(?i)\bAHCI\b")
_READ_RE = re.compile(r"(?i)(?:讀|read)[^0-9]{0,4}(?P<val>\d{3,5})(?:\s*(?:M|MB/s))?")
_WRITE_RE = re.compile(r"(?i)(?:寫|write)[^0-9]{0,4}(?P<val>\d{3,5})(?:\s*(?:M|MB/s))?")

_NAND_RE = re.compile(r"(?i)(3D\s*NAND|TLC|QLC)")
_DRAM_RE = re.compile(r"(?i)\bDRAM\b|快取")
_CONTROLLER_LABEL_RE = re.compile(
    r"(?i)(?:主控|controller)\s*[:：]?\s*(?P<model>[A-Za-z0-9-]{3,})"
)
_CONTROLLER_MODEL_RE = re.compile(r"\b(?P<model>(?:SMI?|PS|IG|MAP|RTS|E)\d{2,4})\b")
_HEATSINK_RE = re.compile(r"(散熱|散熱片|石墨烯)")
_SINGLE_SIDED_RE = re.compile(r"單面")
_LIMIT_RE = re.compile(r"(限購|限組裝)")
_WARRANTY_RE = re.compile(r"[【\[]?(?P<val>[一二三四五六七八九十\d]+)年(?:保)?[】\]]?")

_SPEC_TOKEN_RE = re.compile(
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


def _looks_like_model(token: str) -> bool:
    if not token or len(token) < 5:
        return False
    if _SPEC_TOKEN_RE.match(token):
        return False
    has_alpha = any(ch.isalpha() for ch in token)
    has_digit = any(ch.isdigit() for ch in token)
    return has_alpha and has_digit


def _extract_bracket_model(text: str) -> str | None:
    for m in _BRACKET_CONTENT_RE.finditer(text or ""):
        content = m.group("content") or ""
        for raw in re.split(r"[\s,;/|]+", content):
            token = raw.strip().strip("()[]{}")
            if _looks_like_model(token):
                return token
    return None


def _infer_brand(text: str) -> str | None:
    if not text:
        return None
    for pat, norm in _BRAND_PATTERNS:
        if pat.search(text):
            return norm
    m = re.match(r"[A-Za-z][A-Za-z0-9-]*", text.strip())
    if m:
        return m.group(0).upper()
    return None


def _clean_model(text: str, brand_hint: str | None) -> str | None:
    line = normalize_spaces(strip_leading_note(first_line(text)))
    base = head_before_brackets(line) or line
    base = _BRACKET_REMOVE_RE.sub(" ", base)
    base = _PLUS_SPLIT_RE.split(base, 1)[0].strip()
    if brand_hint:
        base = re.sub(re.escape(brand_hint), " ", base, flags=re.IGNORECASE)
    base = normalize_spaces(base).strip(" -_/|")
    return base or None


def _extract_pcie_gen(text: str) -> int | None:
    m = _PCIE_GEN_RE.search(text or "")
    if not m:
        m = _PCIE_VER_RE.search(text or "")
    if not m:
        return None
    return int(m.group("gen"))


def _extract_seq_speed(text: str, pat: re.Pattern[str]) -> int | None:
    m = pat.search(text or "")
    if not m:
        return None
    return int(m.group("val"))


def _extract_write_after_read(text: str) -> int | None:
    m = _READ_RE.search(text or "")
    if not m:
        return None

    tail = (text or "")[m.end() :]
    m2 = re.search(r"[:/][^0-9]{0,4}(?P<val>\d{3,5})(?!\d)", tail)
    if not m2:
        return None
    return int(m2.group("val"))


def _extract_controller(text: str) -> str | None:
    m = _CONTROLLER_LABEL_RE.search(text or "")
    if m:
        return m.group("model").upper()
    m = _CONTROLLER_MODEL_RE.search(text or "")
    if m:
        return m.group("model").upper()
    return None


_CHINESE_NUM = {
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


def _parse_warranty_years(text: str) -> int | None:
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


def extract_ssd_sku_hint(title: str) -> str | None:
    line = normalized_title_line(title)
    hint = _extract_bracket_model(line)
    if hint:
        return hint
    for m in _SKU_TOKEN_RE.finditer(line or ""):
        token = m.group(0)
        if _looks_like_model(token):
            return token
    return _clean_model(line, None)


def extract_ssd_hints(title: str) -> tuple[str | None, dict[str, object]]:
    text = title or ""
    line = normalized_title_line(text)
    head = head_before_brackets(line)

    brand_hint = _infer_brand(head or line)
    sku_hint = extract_ssd_sku_hint(line)
    model_hint = _clean_model(line, brand_hint)

    capacity_gib = extract_capacity_gib(head) or extract_capacity_gib(line)

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

    if form_factor_hint == '2.5"' and interface_hint is None:
        interface_hint = "SATA"
        protocol_hint = "AHCI"

    if interface_hint == "PCIe" and protocol_hint is None:
        protocol_hint = "NVMe"

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
        "brand_hint": brand_hint,
        "model_hint": model_hint,
        "capacity_gib": capacity_gib,
        "form_factor_hint": form_factor_hint,
        "m2_length_hint": m2_length_hint,
        "interface_hint": interface_hint,
        "pcie_gen_hint": pcie_gen_hint,
        "protocol_hint": protocol_hint,
        "seq_read_mb_s": seq_read_mb_s,
        "seq_write_mb_s": seq_write_mb_s,
        "nand_hint": nand_hint,
        "dram_cache_hint": dram_cache_hint,
        "controller_hint": controller_hint,
        "has_heatsink_hint": has_heatsink_hint,
        "single_sided_hint": single_sided_hint,
        "warranty_years": warranty_years,
        "limit_hint": limit_hint,
    }
    extra = {k: v for k, v in extra.items() if v is not None}
    return sku_hint, extra


__all__ = ["extract_ssd_hints", "extract_ssd_sku_hint"]
