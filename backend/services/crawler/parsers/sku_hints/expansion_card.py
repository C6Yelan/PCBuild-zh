from __future__ import annotations

import re

from .common import first_line, head_before_brackets, normalize_spaces, strip_leading_note

_LEADING_BRACKET_TAGS_RE = re.compile(r"^(?:【[^】]{1,80}】\s*)+")
_MODEL_BUNDLE_SPLIT_RE = re.compile(r"\s*[+＋]\s*")

_PCIE_RE = re.compile(r"PCI-?E|PCIE", flags=re.IGNORECASE)
_PCIE_GEN_RE = re.compile(r"PCI-?E\s*(?:Gen\s*)?([345])(?:\.0)?", flags=re.IGNORECASE)
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

_COUNT_STAR_RE = re.compile(r"(?<![A-Za-z0-9])(?:\*|x|×)\s*(\d+)(?![A-Za-z0-9])", flags=re.IGNORECASE)

_WARRANTY_NUM_RE = re.compile(r"(\d+)\s*年(?!\s*(?:版|款|版本))(?:保固|保)?")
_WARRANTY_ZH_RE = re.compile(r"([一二三四五六七八九十]+)\s*年(?!\s*(?:版|款|版本))(?:保固|保)?")

_BRAND_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{1,}")
_CJK_BRAND_ONLY_RE = re.compile(r"^[\u4e00-\u9fff]{1,6}$")
_TAIL_MODEL_BRACKET_RE = re.compile(r"【\s*([A-Z0-9][A-Z0-9-]{3,})\s*】")
_HYPER_M2_RE = re.compile(r"HYPER\s*M\.2", flags=re.IGNORECASE)
_HYPER_GEN_RE = re.compile(r"GEN\s*([45])", flags=re.IGNORECASE)
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

_SPEC_CLEAN_RE = re.compile(
    r"(?<![A-Za-z0-9])PCI-?E(?![A-Za-z0-9])|(?<![A-Za-z0-9])PCIE(?![A-Za-z0-9])"
    r"|(?<![A-Za-z0-9])GEN\s*[345](?![A-Za-z0-9])|(?<![A-Za-z0-9])X\s*(?:1|4|8|16)(?![A-Za-z0-9])"
    r"|(?<![A-Za-z0-9])\d{1,3}\s*Gbps(?![A-Za-z0-9])|(?<![A-Za-z0-9])\d+\s*埠"
    r"|(?:\*|×)\s*\d+|(?<![A-Za-z0-9])x\s*\d+",
    flags=re.IGNORECASE,
)

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

_COUNT_TOKEN_RE = re.compile(r"(?:\*|×|(?<![A-Za-z0-9])x)\s*(\d+)", flags=re.IGNORECASE)


def _strip_leading_bracket_tags(text: str) -> str:
    return _LEADING_BRACKET_TAGS_RE.sub("", (text or "")).lstrip()


def _normalize_lines(lines: list[str] | None) -> list[str]:
    out: list[str] = []
    for line in lines or []:
        line = normalize_spaces(line)
        if not line or "含稅" in line:
            continue
        out.append(line)
    return out


def _model_head(text: str) -> str:
    line = normalize_spaces(strip_leading_note(first_line(text)))
    line = _strip_leading_bracket_tags(line)
    has_bracket = bool(re.search(r"[（(【]", line))
    head = head_before_brackets(line) or line
    head = _MODEL_BUNDLE_SPLIT_RE.split(head, 1)[0]
    head = re.split(r"[／/|｜]", head, 1)[0]
    head = re.split(r"[，,、:：]", head, 1)[0]
    head = normalize_spaces(head)
    if has_bracket and head and not _SPEC_CLEAN_RE.search(head):
        return head
    cleaned = normalize_spaces(_SPEC_CLEAN_RE.sub(" ", head))
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


def extract_expansion_card_sku_hint(title: str) -> str | None:
    line = normalize_spaces(strip_leading_note(first_line(title)))
    line = _strip_leading_bracket_tags(line)
    head = _model_head(line)
    tail_model = _tail_model_token(line)

    if head:
        # If the cleaned head collapses to a short CJK brand, append a trailing model token.
        if tail_model and _CJK_BRAND_ONLY_RE.fullmatch(head):
            return f"{head} {tail_model}"
        # Preserve Gen4/Gen5 distinction for ASUS Hyper M.2 cards.
        hyper_gen = _hyper_gen_suffix(line)
        if hyper_gen and hyper_gen not in head.upper():
            head = f"{head} {hyper_gen}"
        return head
    fallback = normalize_spaces(head_before_brackets(line) or line)
    if tail_model and _CJK_BRAND_ONLY_RE.fullmatch(fallback):
        return f"{fallback} {tail_model}"
    return fallback or line or None


def _infer_brand(text: str) -> str | None:
    clean = _strip_leading_bracket_tags(text)
    cjk_m = re.match(r"^([\u4e00-\u9fff]{1,20})", clean or "")
    if cjk_m:
        return cjk_m.group(1)
    for m in _BRAND_TOKEN_RE.finditer(clean or ""):
        token = m.group(0).upper()
        if token in _BRAND_IGNORE:
            continue
        return token
    return None


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
            return int(m.group(1))
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


def _extract_keyword_count(texts: list[str], keyword_re: re.Pattern[str], before_keyword: str | None = None) -> int | None:
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
            forward = t[kw.end(): min(len(t), kw.end() + 20)]
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


def _parse_zh_number(raw: str) -> int | None:
    if not raw:
        return None
    if raw.isdigit():
        return int(raw)
    if raw in _CHINESE_NUM:
        return _CHINESE_NUM[raw]
    if raw.startswith("十") and len(raw) == 2 and raw[1] in _CHINESE_NUM:
        return 10 + _CHINESE_NUM[raw[1]]
    if len(raw) == 2 and raw[0] in _CHINESE_NUM and raw[1] == "十":
        return _CHINESE_NUM[raw[0]] * 10
    return None


def _extract_warranty_years(texts: list[str]) -> int | None:
    candidates: list[int] = []
    for text in texts:
        for m in _WARRANTY_NUM_RE.finditer(text or ""):
            candidates.append(int(m.group(1)))
        for m in _WARRANTY_ZH_RE.finditer(text or ""):
            yrs = _parse_zh_number(m.group(1))
            if yrs is not None:
                candidates.append(yrs)
    return max(candidates) if candidates else None


def _extract_limit(texts: list[str]) -> str | None:
    for text in texts:
        m = _LIMIT_RE.search(text or "")
        if m:
            return m.group(1)
    return None


def extract_expansion_card_hints(title: str, desc_lines: list[str] | None) -> tuple[str | None, dict[str, object]]:
    line = normalize_spaces(strip_leading_note(first_line(title)))
    desc = _normalize_lines(desc_lines)
    texts = [line] + desc

    sku_hint = extract_expansion_card_sku_hint(line)
    brand_hint = _infer_brand(line)
    model_hint = sku_hint

    card_kind_hint = _extract_kind(texts)

    host_bus_hint = "pcie" if any(_PCIE_RE.search(t or "") for t in texts) else None
    pcie_gen_hint = _extract_pcie_gen(texts, host_bus_hint)
    pcie_lanes_hint = _extract_lanes(texts)

    m2_slot_count_hint = _extract_m2_slots(texts)
    nvme_only_hint = True if any(_NVME_ONLY_RE.search(t or "") for t in texts) else None

    usb4_port_count_hint = _extract_keyword_count(texts, _USB4_RE, r"USB\s*4")
    thunderbolt_port_count_hint = _extract_keyword_count(texts, _THUNDERBOLT_RE, r"Thunderbolt|TB[45]")
    usb_typec_port_count_hint = _extract_keyword_count(texts, _TYPEC_RE, r"Type-?C|TYPEC")
    usb_typea_port_count_hint = _extract_keyword_count(texts, _TYPEA_RE, r"Type-?A|TYPEA")
    sata_port_count_hint = _extract_keyword_count(texts, _SATA_RE, r"SATA")
    rs232_port_count_hint = _extract_keyword_count(texts, _SERIAL_RE, r"RS232|Serial")
    parallel_port_count_hint = _extract_keyword_count(texts, _PARALLEL_RE, r"Parallel|LPT")
    displayport_in_count_hint = _extract_keyword_count(texts, _DISPLAYPORT_RE, r"DisplayPort")
    mini_dp_in_count_hint = _extract_keyword_count(texts, _MINI_DP_RE, r"Mini\s*DP")

    bandwidth_gbps_hint = _extract_bandwidth(texts)
    chipset_hint = _extract_chipset(texts)
    internal_header_hint = _extract_header(texts)
    low_profile_bracket_included_hint = True if any(_SHORT_BRACKET_RE.search(t or "") for t in texts) else None
    platform_support_hint = _extract_platform_support(desc)
    warranty_years = _extract_warranty_years(texts)
    limit_hint = _extract_limit(texts)

    is_bundle = True if any(_BUNDLE_RE.search(t or "") for t in texts) else None
    has_accessory_term = any(_ACCESSORY_RE.search(t or "") for t in texts)
    has_card_term = any(_PCIE_RE.search(t or "") or _CARD_RE.search(t or "") for t in texts)
    is_accessory = True if (has_accessory_term and not has_card_term) else None

    extra: dict[str, object] = {
        "brand_hint": brand_hint,
        "model_hint": model_hint,
        "card_kind_hint": card_kind_hint,
        "host_bus_hint": host_bus_hint,
        "pcie_gen_hint": pcie_gen_hint,
        "pcie_lanes_hint": pcie_lanes_hint,
        "m2_slot_count_hint": m2_slot_count_hint,
        "nvme_only_hint": nvme_only_hint,
        "usb4_port_count_hint": usb4_port_count_hint,
        "thunderbolt_port_count_hint": thunderbolt_port_count_hint,
        "usb_typec_port_count_hint": usb_typec_port_count_hint,
        "usb_typea_port_count_hint": usb_typea_port_count_hint,
        "sata_port_count_hint": sata_port_count_hint,
        "rs232_port_count_hint": rs232_port_count_hint,
        "parallel_port_count_hint": parallel_port_count_hint,
        "displayport_in_count_hint": displayport_in_count_hint,
        "mini_dp_in_count_hint": mini_dp_in_count_hint,
        "bandwidth_gbps_hint": bandwidth_gbps_hint,
        "chipset_hint": chipset_hint,
        "internal_header_hint": internal_header_hint,
        "low_profile_bracket_included_hint": low_profile_bracket_included_hint,
        "platform_support_hint": platform_support_hint,
        "warranty_years": warranty_years,
        "limit_hint": limit_hint,
        "is_bundle": is_bundle,
        "is_accessory": is_accessory,
    }
    return sku_hint, extra
