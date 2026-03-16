from __future__ import annotations

import re

from ..common import head_before_brackets, normalize_spaces
from ..shared_specs import extract_brand_hint as shared_extract_brand_hint
from ..shared_specs import extract_limit_hint
from ..shared_specs import extract_model_hint as shared_extract_model_hint
from ..shared_specs import extract_warranty_years
from ..shared_specs import normalized_title_line
from ..shared_specs import strip_leading_bracket_tags

_MODEL_BUNDLE_SPLIT_RE = re.compile(r"\s*[+＋]\s*")
_PCIE_RE = re.compile(r"PCI-?E|PCIE", flags=re.IGNORECASE)
_PCIE_GEN_RE = re.compile(r"PCI-?E\s*Gen\s*([345])\b|PCI-?E\s*([345])\.0\b", flags=re.IGNORECASE)
_GEN_RE = re.compile(r"GEN\s*([345])", flags=re.IGNORECASE)
_LANES_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:X\s*(1|4|8|16)|(1|4|8|16)\s*X)(?![A-Za-z0-9])",
    flags=re.IGNORECASE,
)

_M2_RE = re.compile(r"M\.2|NVME|HYPER\s*M\.2|轉接卡", flags=re.IGNORECASE)
_M2_COUNT_RE = re.compile(r"(\d+)\s*(?:個|條|埠)\s*M\.2|M\.2[^0-9]{0,8}(\d+)\s*(?:個|條|埠)", flags=re.IGNORECASE)
_PORT_COUNT_RE = re.compile(r"(\d+)\s*埠")
_NVME_ONLY_RE = re.compile(r"限\s*NVME|NVME\s*ONLY", flags=re.IGNORECASE)

_USB4_RE = re.compile(r"(?<![A-Za-z0-9])USB\s*4(?![A-Za-z0-9])", flags=re.IGNORECASE)
_THUNDERBOLT_RE = re.compile(r"Thunderbolt|(?<![A-Za-z0-9])TB[45](?![A-Za-z0-9])", flags=re.IGNORECASE)
_USB_RE = re.compile(r"USB|Type-?C|Type-?A|GEN\s*2x2|GEN\s*2", flags=re.IGNORECASE)
_SATA_RE = re.compile(r"SATA", flags=re.IGNORECASE)
_SERIAL_RE = re.compile(r"RS232|Serial", flags=re.IGNORECASE)
_PARALLEL_RE = re.compile(r"Parallel|LPT", flags=re.IGNORECASE)
_RAID_RE = re.compile(r"RAID", flags=re.IGNORECASE)

_TYPEC_RE = re.compile(r"Type-?C|TYPEC", flags=re.IGNORECASE)
_TYPEA_RE = re.compile(r"Type-?A|TYPEA", flags=re.IGNORECASE)
_DISPLAYPORT_RE = re.compile(r"DisplayPort", flags=re.IGNORECASE)
_MINI_DP_RE = re.compile(r"Mini\s*DP", flags=re.IGNORECASE)
_GBPS_RE = re.compile(r"(?<![A-Za-z0-9])(\d{2,3})\s*Gbps", flags=re.IGNORECASE)
_CHIPSET_RE = re.compile(r"ASM\s*\d{4}|ASMedia|Renesas|JMicron|JMB\s*\d+|Marvell\s*\d+", flags=re.IGNORECASE)
_HEADER_RE = re.compile(r"主板\s*20Pin\s*Type-?C|20Pin\s*Type-?C|USB\s*19\s*pin|USB19pin|19Pin|20Pin", flags=re.IGNORECASE)
_SHORT_BRACKET_RE = re.compile(r"內附短擋片|短擋片|short\s*bracket", flags=re.IGNORECASE)
_PLATFORM_RE = re.compile(r"支援|平台")

_LIMIT_RE = re.compile(r"(限組裝|限購|限量|客訂)")
_BUNDLE_RE = re.compile(r"(大全配|套裝|組合|bundle)", flags=re.IGNORECASE)
_ACCESSORY_RE = re.compile(r"轉接線|延長線|線材|轉接頭|配件", flags=re.IGNORECASE)
_CARD_RE = re.compile(r"CARD|轉接卡|擴充卡", flags=re.IGNORECASE)

_CJK_BRAND_ONLY_RE = re.compile(r"^[\u4e00-\u9fff]{1,6}$")
_TAIL_MODEL_BRACKET_RE = re.compile(r"【\s*([A-Z0-9][A-Z0-9-]{3,})\s*】")
_HYPER_M2_RE = re.compile(r"HYPER\s*M\.2", flags=re.IGNORECASE)
_HYPER_GEN_RE = re.compile(r"GEN\s*([45])", flags=re.IGNORECASE)
_COUNT_TOKEN_RE = re.compile(r"(?:\*|×|(?<![A-Za-z0-9])x)\s*(\d+)", flags=re.IGNORECASE)
_BRAND_IGNORE = {
    "PCI",
    "PCIE",
    "USB",
    "USB4",
    "NVME",
    "SSD",
    "SATA",
    "RS232",
    "PARALLEL",
    "GEN",
    "CARD",
    "TYPE",
    "DP",
    "TB4",
    "TB5",
}


def _extract_keyword_count(
    texts: list[str],
    keyword_re: re.Pattern[str],
    *,
    before_keyword: str | None = None,
) -> int | None:
    zh_map = {"雙": 2, "兩": 2, "三": 3, "四": 4}
    label_re = re.compile(before_keyword, flags=re.IGNORECASE) if before_keyword else keyword_re
    for text in texts:
        t = text or ""
        for kw in keyword_re.finditer(t):
            start = max(0, kw.start() - 10)
            end = min(len(t), kw.end() + 20)
            window = t[start:end]
            if before_keyword and not label_re.search(window):
                continue
            forward = t[kw.end() : min(len(t), kw.end() + 20)]
            m = _COUNT_TOKEN_RE.search(forward)
            if m:
                return int(m.group(1))
            m = _PORT_COUNT_RE.search(window)
            if m:
                return int(m.group(1))
            for zh, val in zh_map.items():
                if zh in window:
                    return val
    return None

_SPEC_CLEAN_RE = re.compile(
    r"(?<![A-Za-z0-9])PCI-?E(?![A-Za-z0-9])|(?<![A-Za-z0-9])PCIE(?![A-Za-z0-9])"
    r"|(?<![A-Za-z0-9])GEN\s*[345](?![A-Za-z0-9])|(?<![A-Za-z0-9])X\s*(?:1|4|8|16)(?![A-Za-z0-9])"
    r"|(?<![A-Za-z0-9])\d{1,3}\s*Gbps(?![A-Za-z0-9])|(?<![A-Za-z0-9])\d+\s*埠"
    r"|(?:\*|×)\s*\d+|(?<![A-Za-z0-9])x\s*\d+",
    flags=re.IGNORECASE,
)

_KIND_RULES: list[tuple[re.Pattern[str], str]] = [
    (_THUNDERBOLT_RE, "thunderbolt"),
    (_USB4_RE, "usb4"),
    (_USB_RE, "usb"),
    (_M2_RE, "m2_adapter"),
    (_SATA_RE, "sata"),
    (_SERIAL_RE, "serial"),
    (_PARALLEL_RE, "parallel"),
    (_RAID_RE, "raid"),
]


def _model_head(text: str) -> str:
    line = strip_leading_bracket_tags(normalized_title_line(text))
    has_bracket = bool(re.search(r"[（(【]", line))
    head = shared_extract_model_hint(line, bundle_split_re=_MODEL_BUNDLE_SPLIT_RE)
    if has_bracket and head and not _SPEC_CLEAN_RE.search(head):
        return head
    cleaned = shared_extract_model_hint(
        line,
        bundle_split_re=_MODEL_BUNDLE_SPLIT_RE,
        clean_pattern=_SPEC_CLEAN_RE,
    )
    return cleaned or head


def _tail_model_token(text: str) -> str | None:
    last: re.Match[str] | None = None
    for m in _TAIL_MODEL_BRACKET_RE.finditer(text or ""):
        last = m
    if not last:
        return None
    trailing = (text[last.end() :] if text else "").strip()
    if trailing and trailing not in {")", "）"}:
        return None
    return last.group(1)


def _hyper_gen_suffix(text: str) -> str | None:
    if not _HYPER_M2_RE.search(text or ""):
        return None
    m = _HYPER_GEN_RE.search(text or "")
    if not m:
        return None
    return f"GEN {m.group(1)}"


def extract_expansion_card_model_hint(title: str) -> str | None:
    line = strip_leading_bracket_tags(normalized_title_line(title))
    head = _model_head(line)
    tail_model = _tail_model_token(line)
    if head:
        if tail_model and _CJK_BRAND_ONLY_RE.fullmatch(head):
            return f"{head} {tail_model}"
        hyper_gen = _hyper_gen_suffix(line)
        if hyper_gen and hyper_gen not in head.upper():
            head = f"{head} {hyper_gen}"
        return head
    fallback = normalize_spaces(head_before_brackets(line) or line)
    if tail_model and _CJK_BRAND_ONLY_RE.fullmatch(fallback):
        return f"{fallback} {tail_model}"
    return fallback or line or None


def extract_expansion_card_brand_hint(text: str) -> str | None:
    return shared_extract_brand_hint(
        text,
        strip_bracket_tags=True,
        allow_cjk_prefix=True,
        ignore_tokens=_BRAND_IGNORE,
    )


def _extract_kind(texts: list[str]) -> str:
    for text in texts:
        for pat, kind in _KIND_RULES:
            if pat.search(text or ""):
                return kind
    return "other"


def _extract_pcie_gen(texts: list[str], host_bus_hint: str | None) -> int | None:
    for text in texts:
        m = _PCIE_GEN_RE.search(text or "")
        if m:
            return int(m.group(1) or m.group(2))
    if host_bus_hint == "pcie":
        for text in texts:
            m = _GEN_RE.search(text or "")
            if m:
                return int(m.group(1))
    return None


def _extract_lanes(texts: list[str]) -> int | None:
    for text in texts:
        m = _LANES_RE.search(text or "")
        if m:
            val = m.group(1) or m.group(2)
            if val:
                return int(val)
    return None


def _extract_m2_slots(texts: list[str]) -> int | None:
    for text in texts:
        t = text or ""
        if not _M2_RE.search(t):
            continue
        m = _M2_COUNT_RE.search(t)
        if m:
            val = m.group(1) or m.group(2)
            if val:
                return int(val)
        m = _PORT_COUNT_RE.search(t)
        if m:
            return int(m.group(1))
    return None


def _extract_bandwidth(texts: list[str]) -> int | None:
    for text in texts:
        m = _GBPS_RE.search(text or "")
        if m:
            return int(m.group(1))
    return None


def _extract_chipset(texts: list[str]) -> str | None:
    for text in texts:
        m = _CHIPSET_RE.search(text or "")
        if m:
            return normalize_spaces(m.group(0))
    return None


def _extract_header(texts: list[str]) -> str | None:
    for text in texts:
        m = _HEADER_RE.search(text or "")
        if m:
            return normalize_spaces(m.group(0))
    return None


def _extract_platform_support(lines: list[str]) -> str | None:
    for line in lines:
        if _PLATFORM_RE.search(line or ""):
            return line.strip()
    return None


def extract_expansion_card_spec_hints(
    *,
    line: str,
    desc: list[str],
    texts: list[str],
) -> dict[str, object]:
    card_kind_hint = _extract_kind(texts)
    host_bus_hint = "pcie" if any(_PCIE_RE.search(t or "") for t in texts) else None
    pcie_gen_hint = _extract_pcie_gen(texts, host_bus_hint)
    pcie_lanes_hint = _extract_lanes(texts)
    m2_slot_count_hint = _extract_m2_slots(texts)
    nvme_only_hint = True if any(_NVME_ONLY_RE.search(t or "") for t in texts) else None
    has_accessory_term = any(_ACCESSORY_RE.search(t or "") for t in texts)
    has_card_term = any(_PCIE_RE.search(t or "") or _CARD_RE.search(t or "") for t in texts)

    return {
        "card_kind_hint": card_kind_hint,
        "host_bus_hint": host_bus_hint,
        "pcie_gen_hint": pcie_gen_hint,
        "pcie_lanes_hint": pcie_lanes_hint,
        "m2_slot_count_hint": m2_slot_count_hint,
        "nvme_only_hint": nvme_only_hint,
        "usb4_port_count_hint": _extract_keyword_count(texts, _USB4_RE, before_keyword=r"USB\s*4"),
        "thunderbolt_port_count_hint": _extract_keyword_count(texts, _THUNDERBOLT_RE, before_keyword=r"Thunderbolt|TB[45]"),
        "usb_typec_port_count_hint": _extract_keyword_count(texts, _TYPEC_RE, before_keyword=r"Type-?C|TYPEC"),
        "usb_typea_port_count_hint": _extract_keyword_count(texts, _TYPEA_RE, before_keyword=r"Type-?A|TYPEA"),
        "sata_port_count_hint": _extract_keyword_count(texts, _SATA_RE, before_keyword=r"SATA"),
        "rs232_port_count_hint": _extract_keyword_count(texts, _SERIAL_RE, before_keyword=r"RS232|Serial"),
        "parallel_port_count_hint": _extract_keyword_count(texts, _PARALLEL_RE, before_keyword=r"Parallel|LPT"),
        "displayport_in_count_hint": _extract_keyword_count(texts, _DISPLAYPORT_RE, before_keyword=r"DisplayPort"),
        "mini_dp_in_count_hint": _extract_keyword_count(texts, _MINI_DP_RE, before_keyword=r"Mini\s*DP"),
        "bandwidth_gbps_hint": _extract_bandwidth(texts),
        "chipset_hint": _extract_chipset(texts),
        "internal_header_hint": _extract_header(texts),
        "low_profile_bracket_included_hint": True if any(_SHORT_BRACKET_RE.search(t or "") for t in texts) else None,
        "platform_support_hint": _extract_platform_support(desc),
        "warranty_years": extract_warranty_years(texts),
        "limit_hint": extract_limit_hint(texts, _LIMIT_RE),
        "is_bundle": True if any(_BUNDLE_RE.search(t or "") for t in texts) else None,
        "is_accessory": True if (has_accessory_term and not has_card_term) else None,
    }
