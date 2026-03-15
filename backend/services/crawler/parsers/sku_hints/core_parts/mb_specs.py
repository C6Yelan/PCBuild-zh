from __future__ import annotations

import re

from ..common import first_line, head_before_brackets, normalize_spaces

_BUNDLE_RE = re.compile(r"(大全配|套裝|優惠組合|組合|主題.*(大全配|套裝))", flags=re.IGNORECASE)
_BUNDLE_PLUS_RE = re.compile(r"(機殼|電源|水冷|顯卡|顯示卡|散熱|散熱器|風扇)", flags=re.IGNORECASE)

_BRAND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:\bASUS\b|華碩)", flags=re.IGNORECASE), "ASUS"),
    (re.compile(r"(?:\bMSI\b|微星)", flags=re.IGNORECASE), "MSI"),
    (re.compile(r"(?:\bGIGABYTE\b|技嘉)", flags=re.IGNORECASE), "GIGABYTE"),
    (re.compile(r"(?:\bASROCK\b|華擎)", flags=re.IGNORECASE), "ASRock"),
    (re.compile(r"(?:\bBIOSTAR\b|映泰)", flags=re.IGNORECASE), "BIOSTAR"),
]

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

_STOPWORDS = {
    "ATX",
    "M-ATX",
    "MATX",
    "MICRO",
    "E-ATX",
    "ITX",
    "MINI-ITX",
    "CEB",
    "EEB",
    "DDR4",
    "DDR5",
    "WIFI6",
    "WIFI6E",
    "WIFI7",
    "LAN",
    "RGB",
    "ARGB",
}

_VARIANT_ALIASES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\bBTF\b"), "BTF"),
    (re.compile(r"(?i)\bPROJECT\s*ZERO\b"), "PZ"),
    (re.compile(r"(?i)\bPZ\b"), "PZ"),
    (re.compile(r"(?i)\bSTEALTH\b"), "STEALTH"),
]


def infer_mb_brand_hint(title: str) -> str | None:
    text = (title or "").strip()
    if not text:
        return None
    for pat, norm in _BRAND_PATTERNS:
        if pat.search(text):
            return norm
    return None


def extract_mb_head(title: str) -> str:
    line = first_line(title)
    if not line:
        return ""
    return normalize_spaces(head_before_brackets(line))


def _normalize_form_factor(raw: str | None) -> str | None:
    if not raw:
        return None
    u = raw.upper().replace("_", "-")
    if u in ("M-ATX", "MATX", "MICRO-ATX", "MICRO ATX", "MICROATX"):
        return "mATX"
    if u in ("MINI-ITX", "MINI ITX", "MINIITX", "ITX"):
        return "ITX"
    if u in ("E-ATX", "EATX"):
        return "E-ATX"
    if u in ("ATX", "CEB", "EEB"):
        return u
    return raw


def _extract_label_value(text: str, label: str) -> str | None:
    if not text:
        return None
    pattern = re.compile(
        rf"(?:^|[\s\n]){re.escape(label)}\s*[:：]\s*(?P<val>.+?)(?=(?:\s+[\w\u4e00-\u9fff]{{1,8}}\s*[:：])|$)",
        flags=re.IGNORECASE | re.DOTALL,
    )
    m = pattern.search(text)
    return m.group("val").strip() if m else None


def _normalize_socket(text: str | None, *, allow_bare: bool) -> str | None:
    if not text:
        return None
    if re.search(r"\bS?TR5\b", text, flags=re.IGNORECASE):
        return "sTR5"
    if re.search(r"\bS?WRX8\b", text, flags=re.IGNORECASE):
        return "sWRX8"
    m = re.search(r"\bLGA\s*(\d{3,4})\b", text, flags=re.IGNORECASE)
    if m:
        return f"LGA{m.group(1)}"
    m = re.search(r"\bAM\s*([45])\b", text, flags=re.IGNORECASE)
    if m:
        return f"AM{m.group(1)}"
    if allow_bare:
        m = re.search(r"(?<!\d)(\d{3,4})(?!\d)", text)
        if m:
            return f"LGA{m.group(1)}"
    return None


def extract_mb_chipset(text: str | None) -> str | None:
    if not text:
        return None
    for pat in (_CHIPSET_PRIMARY_RE, _CHIPSET_E_SUFFIX_RE, _CHIPSET_MAIN_RE, _CHIPSET_2DIGIT_RE):
        for m in pat.finditer(text):
            chip = m.group("chip").upper()
            if chip in _CHIPSET_EXCLUDE:
                continue
            return chip
    return None


def infer_mb_bundle(head: str) -> bool:
    if not head:
        return False
    if _BUNDLE_RE.search(head):
        return True
    if re.search(r"[+＋]", head) and _BUNDLE_PLUS_RE.search(head):
        return True
    return False


def infer_mb_socket_from_chipset(chipset: str | None) -> str | None:
    if not chipset:
        return None
    c = chipset.upper()
    if c in _AMD_AM5_CHIPSETS:
        return "AM5"
    if c in _AMD_AM4_CHIPSETS:
        return "AM4"
    if c in _AMD_STR5_CHIPSETS:
        return "sTR5"
    if c in _AMD_SWRX8_CHIPSETS:
        return "sWRX8"
    if c in _INTEL_LGA1851_CHIPSETS:
        return "LGA1851"
    if c in _INTEL_LGA1700_CHIPSETS:
        return "LGA1700"
    if c in _INTEL_LGA1200_CHIPSETS:
        return "LGA1200"
    if c in _INTEL_LGA1151_CHIPSETS:
        return "LGA1151"
    if c in _INTEL_LGA1150_CHIPSETS:
        return "LGA1150"
    if c == "W790":
        return "LGA4677"
    return None


def extract_mb_sku_model_hint(title: str) -> str | None:
    if not title:
        return None
    head = extract_mb_head(title)
    variant: str | None = None
    for pat, norm in _VARIANT_ALIASES:
        if pat.search(head):
            variant = norm
            break
    tokens = [t for t in head.split(" ") if t]
    idx = None
    for i, token in enumerate(tokens):
        if any(ch.isdigit() for ch in token):
            idx = i
            break
    if idx is None:
        return variant
    picked: list[str] = []
    for token in tokens[idx:]:
        token = token.strip().strip(",/")
        if token.upper() in _STOPWORDS:
            break
        if len(token) > 18:
            break
        picked.append(token)
        if len(picked) >= 4:
            break
    base = " ".join(picked).strip()
    if not base:
        return variant
    if variant and variant not in base.upper():
        return f"{base} {variant}"
    return base


def extract_mb_spec_hints(
    *,
    title: str,
    head: str,
    sku_hint: str | None,
) -> dict[str, object]:
    chipset_hint = extract_mb_chipset(sku_hint) or extract_mb_chipset(head) or extract_mb_chipset(title)
    cpu_field = _extract_label_value(title or "", "CPU")
    socket_hint = _normalize_socket(cpu_field, allow_bare=True)
    if not socket_hint:
        socket_hint = _normalize_socket(head, allow_bare=False)
    if not socket_hint:
        sock_m = _CPU_SOCKET_RE.search(title or "")
        socket_hint = _normalize_socket(sock_m.group("sock") if sock_m else None, allow_bare=False)
    if not socket_hint:
        bare_lga = re.search(r"(?<!\d)(1700|1851|1200|1151|1150|4677)(?!\d)", title or "")
        if bare_lga:
            socket_hint = f"LGA{bare_lga.group(1)}"
    if not socket_hint:
        socket_hint = infer_mb_socket_from_chipset(chipset_hint)

    form_m = _FORM_FACTOR_RE.search(head or "") or _FORM_FACTOR_RE.search(title or "")
    form_factor_hint = _normalize_form_factor(form_m.group("form") if form_m else None)

    mem_re = re.compile(
        r"(?<![A-Za-z0-9])(?:DDR(?P<ddr_gen>[345])|D(?P<d_gen>[45]))(?![A-Za-z0-9])",
        flags=re.IGNORECASE,
    )
    m = mem_re.search(sku_hint or "") or mem_re.search(head or "") or mem_re.search(title or "")
    if m:
        gen = m.group("ddr_gen") or m.group("d_gen")
        memory_type_hint = f"DDR{gen}"
    else:
        memory_type_hint = None

    if memory_type_hint is None:
        if socket_hint in ("AM4", "sWRX8", "LGA1200"):
            memory_type_hint = "DDR4"
        elif socket_hint in ("AM5", "sTR5", "LGA1851", "LGA4677"):
            memory_type_hint = "DDR5"
        elif socket_hint == "LGA1150":
            memory_type_hint = "DDR3"
        elif chipset_hint in ("WRX80",):
            memory_type_hint = "DDR4"
        elif chipset_hint in ("TRX50", "WRX90"):
            memory_type_hint = "DDR5"

    return {
        "chipset_hint": chipset_hint,
        "socket_hint": socket_hint,
        "form_factor_hint": form_factor_hint,
        "memory_type_hint": memory_type_hint,
        "is_bundle": infer_mb_bundle(head),
    }
