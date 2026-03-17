from __future__ import annotations

import re

from ..common import head_before_brackets
from ..shared_specs import extract_capacity_gib
from ..shared_specs import normalized_title_line
from .ssd_identity_specs import clean_ssd_model, extract_ssd_sku_hint, infer_ssd_brand

_FORM_25_RE = re.compile(r"2\.5吋|2\.5\"", flags=re.IGNORECASE)
_M2_RE = re.compile(r"\bM\.2\b", flags=re.IGNORECASE)
_M2_LEN_RE = re.compile(r"\b(22(?:30|42|60|80|110))\b")
_PCIE_GEN_RE = re.compile(r"(?i)\bGEN\s*(?P<gen>[345])\b")
_PCIE_VER_RE = re.compile(r"(?i)PCI-?E\s*(?P<gen>[345])(?:\.0)?")
_PCIE_RE = re.compile(r"(?i)\bPCI-?E\b")
_NVME_RE = re.compile(r"(?i)\bNVME\b")
_SATA_RE = re.compile(r"(?i)\bSATA\b")
_READ_RE = re.compile(r"(?i)(?:讀|read)[^0-9]{0,4}(?P<val>\d{3,5})(?:\s*(?:M|MB/s))?")
_WRITE_RE = re.compile(r"(?i)(?:寫|write)[^0-9]{0,4}(?P<val>\d{3,5})(?:\s*(?:M|MB/s))?")
_NAND_RE = re.compile(r"(?i)(3D\s*NAND|TLC|QLC)")
_DRAM_RE = re.compile(r"(?i)\bDRAM\b|快取")
_CONTROLLER_LABEL_RE = re.compile(r"(?i)(?:主控|controller)\s*[:：]?\s*(?P<model>[A-Za-z0-9-]{3,})")
_CONTROLLER_MODEL_RE = re.compile(r"\b(?P<model>(?:SMI?|PS|IG|MAP|RTS|E)\d{2,4})\b")
_HEATSINK_RE = re.compile(r"(散熱|散熱片|石墨烯)")
_SINGLE_SIDED_RE = re.compile(r"單面")
_LIMIT_RE = re.compile(r"(限購|限組裝)")
_WARRANTY_RE = re.compile(r"[【\[]?(?P<val>[一二三四五六七八九十\d]+)年(?:保)?[】\]]?")
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


def _extract_pcie_gen(text: str) -> int | None:
    match = _PCIE_GEN_RE.search(text or "")
    if not match:
        match = _PCIE_VER_RE.search(text or "")
    if not match:
        return None
    return int(match.group("gen"))


def _extract_seq_speed(text: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(text or "")
    if not match:
        return None
    return int(match.group("val"))


def _extract_write_after_read(text: str) -> int | None:
    match = _READ_RE.search(text or "")
    if not match:
        return None
    tail = (text or "")[match.end() :]
    match = re.search(r"[:/][^0-9]{0,4}(?P<val>\d{3,5})(?!\d)", tail)
    if not match:
        return None
    return int(match.group("val"))


def _extract_controller(text: str) -> str | None:
    match = _CONTROLLER_LABEL_RE.search(text or "")
    if match:
        return match.group("model").upper()
    match = _CONTROLLER_MODEL_RE.search(text or "")
    if match:
        return match.group("model").upper()
    return None


def _parse_warranty_years(text: str) -> int | None:
    match = _WARRANTY_RE.search(text or "")
    if not match:
        return None
    raw = match.group("val")
    if raw.isdigit():
        return int(raw)
    if raw in _CHINESE_NUM:
        return _CHINESE_NUM[raw]
    if raw.startswith("十") and len(raw) == 2 and raw[1] in _CHINESE_NUM:
        return 10 + _CHINESE_NUM[raw[1]]
    if len(raw) == 2 and raw[0] in _CHINESE_NUM and raw[1] == "十":
        return _CHINESE_NUM[raw[0]] * 10
    return None


def extract_ssd_hints(title: str) -> tuple[str | None, dict[str, object]]:
    text = title or ""
    line = normalized_title_line(text)
    head = head_before_brackets(line)

    brand_hint = infer_ssd_brand(head or line)
    sku_hint = extract_ssd_sku_hint(line)
    model_hint = clean_ssd_model(line, brand_hint)
    capacity_gib = extract_capacity_gib(head) or extract_capacity_gib(line)

    form_factor_hint = None
    if _FORM_25_RE.search(line):
        form_factor_hint = '2.5"'
    elif _M2_RE.search(line):
        form_factor_hint = "M.2"

    m2_length_hint = None
    if form_factor_hint == "M.2":
        match = _M2_LEN_RE.search(line or "")
        if match:
            m2_length_hint = int(match.group(1))

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
    nand_match = _NAND_RE.search(line)
    if nand_match:
        nand_hint = nand_match.group(1).upper().replace(" ", "")
        if nand_hint == "3DNAND":
            nand_hint = "3D NAND"

    dram_cache_hint = True if _DRAM_RE.search(line) else None
    controller_hint = _extract_controller(line)
    has_heatsink_hint = True if _HEATSINK_RE.search(line) else None
    single_sided_hint = True if _SINGLE_SIDED_RE.search(line) else None
    warranty_years = _parse_warranty_years(line)

    limit_hint = None
    match = _LIMIT_RE.search(line)
    if match:
        limit_hint = match.group(1)

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
    return sku_hint, extra
