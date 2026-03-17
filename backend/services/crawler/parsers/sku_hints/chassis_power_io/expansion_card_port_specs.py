from __future__ import annotations

import re

from ..common import normalize_spaces
from .expansion_card_bus_specs import COUNT_TOKEN_RE, PORT_COUNT_RE, USB4_RE

THUNDERBOLT_RE = re.compile(r"Thunderbolt|(?<![A-Za-z0-9])TB[45](?![A-Za-z0-9])", flags=re.IGNORECASE)
SATA_RE = re.compile(r"SATA", flags=re.IGNORECASE)
SERIAL_RE = re.compile(r"RS232|Serial", flags=re.IGNORECASE)
PARALLEL_RE = re.compile(r"Parallel|LPT", flags=re.IGNORECASE)
TYPEC_RE = re.compile(r"Type-?C|TYPEC", flags=re.IGNORECASE)
TYPEA_RE = re.compile(r"Type-?A|TYPEA", flags=re.IGNORECASE)
DISPLAYPORT_RE = re.compile(r"DisplayPort", flags=re.IGNORECASE)
MINI_DP_RE = re.compile(r"Mini\s*DP", flags=re.IGNORECASE)
GBPS_RE = re.compile(r"(?<![A-Za-z0-9])(\d{2,3})\s*Gbps", flags=re.IGNORECASE)
CHIPSET_RE = re.compile(r"ASM\s*\d{4}|ASMedia|Renesas|JMicron|JMB\s*\d+|Marvell\s*\d+", flags=re.IGNORECASE)
HEADER_RE = re.compile(r"主板\s*20Pin\s*Type-?C|20Pin\s*Type-?C|USB\s*19\s*pin|USB19pin|19Pin|20Pin", flags=re.IGNORECASE)
SHORT_BRACKET_RE = re.compile(r"內附短擋片|短擋片|short\s*bracket", flags=re.IGNORECASE)
PLATFORM_RE = re.compile(r"支援|平台")


def extract_expansion_card_keyword_count(
    texts: list[str],
    keyword_re: re.Pattern[str],
    *,
    before_keyword: str | None = None,
) -> int | None:
    zh_map = {"雙": 2, "兩": 2, "三": 3, "四": 4}
    label_re = re.compile(before_keyword, flags=re.IGNORECASE) if before_keyword else keyword_re
    for text in texts:
        candidate = text or ""
        for keyword in keyword_re.finditer(candidate):
            start = max(0, keyword.start() - 10)
            end = min(len(candidate), keyword.end() + 20)
            window = candidate[start:end]
            if before_keyword and not label_re.search(window):
                continue
            count = COUNT_TOKEN_RE.search(candidate[keyword.end() : min(len(candidate), keyword.end() + 20)])
            if count:
                return int(count.group(1))
            count = PORT_COUNT_RE.search(window)
            if count:
                return int(count.group(1))
            for zh, value in zh_map.items():
                if zh in window:
                    return value
    return None


def extract_expansion_card_bandwidth(texts: list[str]) -> int | None:
    for text in texts:
        match = GBPS_RE.search(text or "")
        if match:
            return int(match.group(1))
    return None


def extract_expansion_card_chipset(texts: list[str]) -> str | None:
    for text in texts:
        match = CHIPSET_RE.search(text or "")
        if match:
            return normalize_spaces(match.group(0))
    return None


def extract_expansion_card_header(texts: list[str]) -> str | None:
    for text in texts:
        match = HEADER_RE.search(text or "")
        if match:
            return normalize_spaces(match.group(0))
    return None


def extract_expansion_card_platform_support(lines: list[str]) -> str | None:
    for line in lines:
        if PLATFORM_RE.search(line or ""):
            return line.strip()
    return None


def extract_expansion_card_low_profile_bracket(texts: list[str]) -> bool | None:
    return True if any(SHORT_BRACKET_RE.search(text or "") for text in texts) else None


__all__ = [
    "DISPLAYPORT_RE",
    "MINI_DP_RE",
    "PARALLEL_RE",
    "SATA_RE",
    "SERIAL_RE",
    "THUNDERBOLT_RE",
    "TYPEA_RE",
    "TYPEC_RE",
    "extract_expansion_card_bandwidth",
    "extract_expansion_card_chipset",
    "extract_expansion_card_header",
    "extract_expansion_card_keyword_count",
    "extract_expansion_card_low_profile_bracket",
    "extract_expansion_card_platform_support",
]
