from __future__ import annotations

import re

PCIE_RE = re.compile(r"PCI-?E|PCIE", flags=re.IGNORECASE)
PCIE_GEN_RE = re.compile(r"PCI-?E\s*Gen\s*([345])\b|PCI-?E\s*([345])\.0\b", flags=re.IGNORECASE)
GEN_RE = re.compile(r"GEN\s*([345])", flags=re.IGNORECASE)
LANES_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:X\s*(1|4|8|16)|(1|4|8|16)\s*X)(?![A-Za-z0-9])",
    flags=re.IGNORECASE,
)
M2_RE = re.compile(r"M\.2|NVME|HYPER\s*M\.2|轉接卡", flags=re.IGNORECASE)
M2_COUNT_RE = re.compile(r"(\d+)\s*(?:個|條|埠)\s*M\.2|M\.2[^0-9]{0,8}(\d+)\s*(?:個|條|埠)", flags=re.IGNORECASE)
PORT_COUNT_RE = re.compile(r"(\d+)\s*埠")
NVME_ONLY_RE = re.compile(r"限\s*NVME|NVME\s*ONLY", flags=re.IGNORECASE)
COUNT_TOKEN_RE = re.compile(r"(?:\*|×|(?<![A-Za-z0-9])x)\s*(\d+)", flags=re.IGNORECASE)
THUNDERBOLT_RE = re.compile(r"Thunderbolt|(?<![A-Za-z0-9])TB[45](?![A-Za-z0-9])", flags=re.IGNORECASE)
USB4_RE = re.compile(r"(?<![A-Za-z0-9])USB\s*4(?![A-Za-z0-9])", flags=re.IGNORECASE)
USB_RE = re.compile(r"USB|Type-?C|Type-?A|GEN\s*2x2|GEN\s*2", flags=re.IGNORECASE)
SATA_RE = re.compile(r"SATA", flags=re.IGNORECASE)
SERIAL_RE = re.compile(r"RS232|Serial", flags=re.IGNORECASE)
PARALLEL_RE = re.compile(r"Parallel|LPT", flags=re.IGNORECASE)
RAID_RE = re.compile(r"RAID", flags=re.IGNORECASE)

KIND_RULES: list[tuple[re.Pattern[str], str]] = [
    (THUNDERBOLT_RE, "thunderbolt"),
    (USB4_RE, "usb4"),
    (USB_RE, "usb"),
    (M2_RE, "m2_adapter"),
    (SATA_RE, "sata"),
    (SERIAL_RE, "serial"),
    (PARALLEL_RE, "parallel"),
    (RAID_RE, "raid"),
]


def extract_expansion_card_kind(texts: list[str]) -> str:
    for text in texts:
        for pattern, kind in KIND_RULES:
            if pattern.search(text or ""):
                return kind
    return "other"


def extract_expansion_card_host_bus(texts: list[str]) -> str | None:
    return "pcie" if any(PCIE_RE.search(text or "") for text in texts) else None


def extract_expansion_card_pcie_gen(texts: list[str], host_bus_hint: str | None) -> int | None:
    for text in texts:
        match = PCIE_GEN_RE.search(text or "")
        if match:
            return int(match.group(1) or match.group(2))
    if host_bus_hint == "pcie":
        for text in texts:
            match = GEN_RE.search(text or "")
            if match:
                return int(match.group(1))
    return None


def extract_expansion_card_pcie_lanes(texts: list[str]) -> int | None:
    for text in texts:
        match = LANES_RE.search(text or "")
        if match:
            value = match.group(1) or match.group(2)
            if value:
                return int(value)
    return None


def extract_expansion_card_m2_slot_count(texts: list[str]) -> int | None:
    for text in texts:
        candidate = text or ""
        if not M2_RE.search(candidate):
            continue
        match = M2_COUNT_RE.search(candidate)
        if match:
            value = match.group(1) or match.group(2)
            if value:
                return int(value)
        match = COUNT_TOKEN_RE.search(candidate)
        if match:
            return int(match.group(1))
        match = PORT_COUNT_RE.search(candidate)
        if match:
            return int(match.group(1))
    return None


def extract_expansion_card_nvme_only(texts: list[str]) -> bool | None:
    return True if any(NVME_ONLY_RE.search(text or "") for text in texts) else None


__all__ = [
    "COUNT_TOKEN_RE",
    "PORT_COUNT_RE",
    "USB4_RE",
    "extract_expansion_card_host_bus",
    "extract_expansion_card_kind",
    "extract_expansion_card_m2_slot_count",
    "extract_expansion_card_nvme_only",
    "extract_expansion_card_pcie_gen",
    "extract_expansion_card_pcie_lanes",
]
