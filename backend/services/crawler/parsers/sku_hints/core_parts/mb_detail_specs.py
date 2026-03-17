from __future__ import annotations

import re

from .mb_identity_specs import extract_mb_head

_BUNDLE_RE = re.compile(r"(大全配|套裝|優惠組合|組合|主題.*(大全配|套裝))", flags=re.IGNORECASE)
_BUNDLE_PLUS_RE = re.compile(r"(機殼|電源|水冷|顯卡|顯示卡|散熱|散熱器|風扇)", flags=re.IGNORECASE)
_CPU_SOCKET_RE = re.compile(
    r"(?<![A-Za-z0-9])(?P<sock>LGA\s*\d{3,4}|AM[45]|s?TR5|s?WRX8)(?![A-Za-z0-9])",
    flags=re.IGNORECASE,
)
_FORM_FACTOR_RE = re.compile(
    r"(?<![A-Za-z0-9])(?P<form>E-?ATX|ATX|M-?ATX|MICRO[ -]?ATX|MATX|MINI[ -]?ITX|ITX|CEB|EEB)(?![A-Za-z0-9])",
    flags=re.IGNORECASE,
)
_CHIPSET_PRIMARY_RE = re.compile(r"\b(?P<chip>WRX90|WRX80|TRX50)(?=[A-Za-z]|\b)", flags=re.IGNORECASE)
_CHIPSET_E_SUFFIX_RE = re.compile(r"\b(?P<chip>(?:B|X)\d{3}E)(?=[A-Za-z]|\b)", flags=re.IGNORECASE)
_CHIPSET_MAIN_RE = re.compile(r"\b(?P<chip>[ABHXZW]\d{3,4})(?=[A-Za-z]|\b)", flags=re.IGNORECASE)
_CHIPSET_2DIGIT_RE = re.compile(r"\b(?P<chip>[ABHZXQ]\d{2})(?=[A-Za-z]|\b)", flags=re.IGNORECASE)
_CHIPSET_EXCLUDE = {"X550", "I225", "I226", "I211", "I210"}
_AMD_AM5_CHIPSETS = {"X870E", "X870", "B850", "B840", "X670E", "X670", "B650E", "B650", "A620"}
_AMD_AM4_CHIPSETS = {"X570", "B550", "A520", "X470", "B450", "A320"}
_INTEL_LGA1851_CHIPSETS = {"Z890", "B860", "H810", "W880"}
_INTEL_LGA1700_CHIPSETS = {"Z790", "H770", "B760", "H760", "H610", "Z690", "H670", "B660", "W680"}
_INTEL_LGA1200_CHIPSETS = {"Z590", "H570", "B560", "H510", "Z490", "H470", "B460", "H410"}
_INTEL_LGA1151_CHIPSETS = {"H110", "H310"}
_INTEL_LGA1150_CHIPSETS = {"H81"}
_AMD_STR5_CHIPSETS = {"TRX50", "WRX90"}
_AMD_SWRX8_CHIPSETS = {"WRX80"}


def extract_mb_spec_hints(
    *,
    title: str,
    head: str,
    sku_hint: str | None,
) -> dict[str, object]:
    chipset_hint = extract_mb_chipset(sku_hint) or extract_mb_chipset(head) or extract_mb_chipset(title)
    cpu_field = extract_mb_label_value(title or "", "CPU")
    socket_hint = normalize_mb_socket(cpu_field, allow_bare=True)
    if not socket_hint:
        socket_hint = normalize_mb_socket(head, allow_bare=False)
    if not socket_hint:
        match = _CPU_SOCKET_RE.search(title or "")
        socket_hint = normalize_mb_socket(match.group("sock") if match else None, allow_bare=False)
    if not socket_hint:
        bare_lga = re.search(r"(?<!\d)(1700|1851|1200|1151|1150|4677)(?!\d)", title or "")
        if bare_lga:
            socket_hint = f"LGA{bare_lga.group(1)}"
    if not socket_hint:
        socket_hint = infer_mb_socket_from_chipset(chipset_hint)

    form_match = _FORM_FACTOR_RE.search(head or "") or _FORM_FACTOR_RE.search(title or "")
    form_factor_hint = normalize_mb_form_factor(form_match.group("form") if form_match else None)

    mem_re = re.compile(
        r"(?<![A-Za-z0-9])(?:DDR(?P<ddr_gen>[345])|D(?P<d_gen>[45]))(?![A-Za-z0-9])",
        flags=re.IGNORECASE,
    )
    match = mem_re.search(sku_hint or "") or mem_re.search(head or "") or mem_re.search(title or "")
    if match:
        gen = match.group("ddr_gen") or match.group("d_gen")
        memory_type_hint = f"DDR{gen}"
    else:
        memory_type_hint = infer_mb_memory_type(socket_hint, chipset_hint)

    return {
        "chipset_hint": chipset_hint,
        "socket_hint": socket_hint,
        "form_factor_hint": form_factor_hint,
        "memory_type_hint": memory_type_hint,
        "is_bundle": infer_mb_bundle(head),
    }


def infer_mb_bundle(head: str) -> bool:
    if not head:
        return False
    return bool(_BUNDLE_RE.search(head) or (re.search(r"[+＋]", head) and _BUNDLE_PLUS_RE.search(head)))


def normalize_mb_form_factor(raw: str | None) -> str | None:
    if not raw:
        return None
    upper = raw.upper().replace("_", "-")
    if upper in ("M-ATX", "MATX", "MICRO-ATX", "MICRO ATX", "MICROATX"):
        return "mATX"
    if upper in ("MINI-ITX", "MINI ITX", "MINIITX", "ITX"):
        return "ITX"
    if upper in ("E-ATX", "EATX"):
        return "E-ATX"
    if upper in ("ATX", "CEB", "EEB"):
        return upper
    return raw


def extract_mb_label_value(text: str, label: str) -> str | None:
    if not text:
        return None
    pattern = re.compile(
        rf"(?:^|[\s\n]){re.escape(label)}\s*[:：]\s*(?P<val>.+?)(?=(?:\s+[\w\u4e00-\u9fff]{{1,8}}\s*[:：])|$)",
        flags=re.IGNORECASE | re.DOTALL,
    )
    match = pattern.search(text)
    if match:
        return match.group("val").strip()
    return None


def normalize_mb_socket(text: str | None, *, allow_bare: bool) -> str | None:
    if not text:
        return None
    if re.search(r"\bS?TR5\b", text, flags=re.IGNORECASE):
        return "sTR5"
    if re.search(r"\bS?WRX8\b", text, flags=re.IGNORECASE):
        return "sWRX8"
    match = re.search(r"\bLGA\s*(\d{3,4})\b", text, flags=re.IGNORECASE)
    if match:
        return f"LGA{match.group(1)}"
    match = re.search(r"\bAM\s*([45])\b", text, flags=re.IGNORECASE)
    if match:
        return f"AM{match.group(1)}"
    if allow_bare:
        match = re.search(r"(?<!\d)(\d{3,4})(?!\d)", text)
        if match:
            return f"LGA{match.group(1)}"
    return None


def extract_mb_chipset(text: str | None) -> str | None:
    if not text:
        return None
    for pattern in (_CHIPSET_PRIMARY_RE, _CHIPSET_E_SUFFIX_RE, _CHIPSET_MAIN_RE, _CHIPSET_2DIGIT_RE):
        for match in pattern.finditer(text):
            chip = match.group("chip").upper()
            if chip in _CHIPSET_EXCLUDE:
                continue
            return chip
    return None


def infer_mb_socket_from_chipset(chipset: str | None) -> str | None:
    if not chipset:
        return None
    chip = chipset.upper()
    if chip in _AMD_AM5_CHIPSETS:
        return "AM5"
    if chip in _AMD_AM4_CHIPSETS:
        return "AM4"
    if chip in _AMD_STR5_CHIPSETS:
        return "sTR5"
    if chip in _AMD_SWRX8_CHIPSETS:
        return "sWRX8"
    if chip in _INTEL_LGA1851_CHIPSETS:
        return "LGA1851"
    if chip in _INTEL_LGA1700_CHIPSETS:
        return "LGA1700"
    if chip in _INTEL_LGA1200_CHIPSETS:
        return "LGA1200"
    if chip in _INTEL_LGA1151_CHIPSETS:
        return "LGA1151"
    if chip in _INTEL_LGA1150_CHIPSETS:
        return "LGA1150"
    if chip == "W790":
        return "LGA4677"
    return None


def infer_mb_memory_type(socket_hint: str | None, chipset_hint: str | None) -> str | None:
    if socket_hint in ("AM4", "sWRX8", "LGA1200"):
        return "DDR4"
    if socket_hint in ("AM5", "sTR5", "LGA1851", "LGA4677"):
        return "DDR5"
    if socket_hint == "LGA1150":
        return "DDR3"
    if chipset_hint in ("WRX80",):
        return "DDR4"
    if chipset_hint in ("TRX50", "WRX90"):
        return "DDR5"
    return None
