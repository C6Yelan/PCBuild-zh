from __future__ import annotations

import re

from ..shared_specs import extract_brand_hint as shared_extract_brand_hint
from ..shared_specs import extract_limit_hint, extract_model_hint as shared_extract_model_hint

_NOTICE_RE = re.compile(r"(提醒|注意事項|說明)")
_PASTE_RE = re.compile(r"(導熱膏|散熱膏|液態金屬|道康膏|涼膏)")
_PAD_RE = re.compile(r"(導熱墊|導熱片|Thermal\s*Pad)", flags=re.IGNORECASE)
_M2_RE = re.compile(r"M\.2", flags=re.IGNORECASE)
_M2_LEN_RE = re.compile(r"\b(22110|2280|2260|2242|2230)\b")
_HEATSINK_RE = re.compile(r"散熱")
_LIQUID_RE = re.compile(r"(水冷|冷排|AIO|一體式)", flags=re.IGNORECASE)
_NOTEBOOK_RE = re.compile(
    r"(筆電|Notebook|NotePal|ErgoStand|散熱墊|散熱座|Cooling\s*Pad|Laptop\s*Cooler|Stand)",
    flags=re.IGNORECASE,
)
_AIR_RE = re.compile(r"散熱器")
_LIMIT_RE = re.compile(r"(限購|限組裝|限量|客訂)")
_BUNDLE_RE = re.compile(r"(大全配|套裝|組合)")
_MOUNT_KIT_RE = re.compile(r"(扣具|安裝套件|固定架|背板|支架)", flags=re.IGNORECASE)
_AIR_HINT_RE = re.compile(r"(塔散|空冷|下吹|風冷|雙塔|單塔)")

_MODEL_REMOVE_RE = re.compile(
    r"(散熱器|散熱膏|導熱膏|散熱墊|導熱墊|導熱片|散熱片|散熱座|筆電散熱座|筆電散熱墊|"
    r"M\.2散熱片|M\.2散熱器|SSD散熱片|SSD散熱器|水冷|冷排|一體式)",
    flags=re.IGNORECASE,
)
_MODEL_HEAD_CLEAN_RE = re.compile(
    rf"{_MODEL_REMOVE_RE.pattern}|{_LIMIT_RE.pattern}",
    flags=re.IGNORECASE,
)
_BRAND_IGNORE = {"CPU", "PWM", "RGB", "ARGB", "AIO", "TDP", "M2", "SSD", "HDD"}

_BRAND_PREFIX_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^利民"), "THERMALRIGHT"),
    (re.compile(r"^酷碼"), "COOLERMASTER"),
    (re.compile(r"^貓頭鷹"), "NOCTUA"),
    (re.compile(r"^喬思伯"), "JONSBO"),
    (re.compile(r"^九州風神"), "DEEPCOOL"),
    (re.compile(r"^銀欣"), "SILVERSTONE"),
    (re.compile(r"^全漢"), "FSP"),
    (re.compile(r"^保銳"), "ENERMAX"),
    (re.compile(r"^微星"), "MSI"),
    (re.compile(r"^華碩"), "ASUS"),
    (re.compile(r"^darkflash", flags=re.IGNORECASE), "DARKFLASH"),
    (re.compile(r"^montech", flags=re.IGNORECASE), "MONTECH"),
    (re.compile(r"^scythe", flags=re.IGNORECASE), "SCYTHE"),
    (re.compile(r"^cougar", flags=re.IGNORECASE), "COUGAR"),
]


def detect_cooler_kind(text: str) -> str:
    if _NOTICE_RE.search(text or ""):
        return "notice"
    if _PASTE_RE.search(text or ""):
        return "thermal_paste"
    if _NOTEBOOK_RE.search(text or ""):
        return "notebook_cooler"
    if _PAD_RE.search(text or ""):
        return "thermal_pad"
    if (_M2_RE.search(text or "") or _M2_LEN_RE.search(text or "")) and _HEATSINK_RE.search(text or ""):
        return "ssd_heatsink"
    if _LIQUID_RE.search(text or ""):
        return "cpu_liquid_aio"
    if _HEATSINK_RE.search(text or "") and (_AIR_HINT_RE.search(text or "") or _AIR_RE.search(text or "")):
        return "cpu_air"
    if _AIR_RE.search(text or "") or _AIR_HINT_RE.search(text or ""):
        return "cpu_air"
    return "other"


def extract_cooler_brand_hint(text: str) -> str | None:
    return shared_extract_brand_hint(
        text,
        prefix_rules=_BRAND_PREFIX_RULES,
        ignore_tokens=_BRAND_IGNORE,
    )


def extract_cooler_model_hint(text: str) -> str | None:
    return shared_extract_model_hint(text, clean_pattern=_MODEL_HEAD_CLEAN_RE)


def extract_cooler_limit_hint(texts: list[str]) -> str | None:
    return extract_limit_hint(texts, _LIMIT_RE)


def infer_cooler_bundle(head: str) -> bool:
    return bool(_BUNDLE_RE.search(head))


def infer_cooler_accessory(line: str, cooler_kind_hint: str) -> bool:
    if _MOUNT_KIT_RE.search(line):
        return True
    return cooler_kind_hint not in ("cpu_air", "cpu_liquid_aio")
