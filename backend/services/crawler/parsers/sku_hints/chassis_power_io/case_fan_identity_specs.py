from __future__ import annotations

import re

from ..shared_specs import extract_model_hint as shared_extract_model_hint
from ..shared_specs import normalized_title_line
from .case_fan_detail_specs import extract_case_fan_pack_count, extract_case_fan_size_mm

_MODEL_BUNDLE_SPLIT_RE = re.compile(r"\s+[+＋]\s+")
_RPM_RANGE_RE = re.compile(r"(?<!\d)(\d{3,5})\s*(?:~|～|-|－)\s*(\d{3,5})\s*RPM", flags=re.IGNORECASE)
_RPM_SINGLE_RE = re.compile(r"(?<!\d)(\d{3,5})\s*RPM", flags=re.IGNORECASE)
_PWM_RE = re.compile(r"(?<![A-Za-z0-9])PWM(?![A-Za-z0-9])", flags=re.IGNORECASE)
_CONTROLLER_REQ_RE = re.compile(r"需[^\n]{0,12}控制器|需搭配[^\n]{0,12}控制器")
_ACCESSORY_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"控制器|controller", flags=re.IGNORECASE), "controller"),
    (re.compile(r"\bHUB\b|集線器|hub", flags=re.IGNORECASE), "hub"),
    (
        re.compile(
            r"擴充線|連接線|延長線|分接線|轉接線|1轉|1分|SST-CPF|PWM\s*擴充線|ARGB\s*連接線|風扇電源擴充線|cable|線材",
            flags=re.IGNORECASE,
        ),
        "cable",
    ),
    (re.compile(r"支架|固定架|bracket", flags=re.IGNORECASE), "bracket"),
    (re.compile(r"燈條|燈效套件|led\s*strip", flags=re.IGNORECASE), "led_strip"),
    (re.compile(r"模組", flags=re.IGNORECASE), "module"),
]


def extract_case_fan_model_hint(text: str) -> str | None:
    line = normalized_title_line(text)
    return shared_extract_model_hint(
        line,
        strip_bracket_tags=True,
        bundle_split_re=_MODEL_BUNDLE_SPLIT_RE,
    )


def detect_case_fan_accessory_hints(texts: list[str]) -> tuple[bool, str | None]:
    bundle_context = False
    for text in texts:
        candidate = text or ""
        if _CONTROLLER_REQ_RE.search(candidate):
            continue
        pack_cnt = extract_case_fan_pack_count([candidate])
        fan_like = bool(
            _RPM_RANGE_RE.search(candidate)
            or _RPM_SINGLE_RE.search(candidate)
            or _PWM_RE.search(candidate)
            or (extract_case_fan_size_mm([candidate]) is not None)
            or ("風扇" in candidate)
        )
        if pack_cnt is not None and fan_like:
            bundle_context = True
            break
    if bundle_context:
        return False, None
    for text in texts:
        candidate = text or ""
        if _CONTROLLER_REQ_RE.search(candidate):
            continue
        pack_cnt = extract_case_fan_pack_count([candidate])
        fan_like = bool(
            _RPM_RANGE_RE.search(candidate)
            or _RPM_SINGLE_RE.search(candidate)
            or _PWM_RE.search(candidate)
            or (extract_case_fan_size_mm([candidate]) is not None)
            or ("風扇" in candidate)
        )
        bundle_like = (pack_cnt is not None) and fan_like
        for pattern, kind in _ACCESSORY_RULES:
            if kind in ("controller", "hub") and bundle_like:
                continue
            if pattern.search(candidate):
                return True, kind
    return False, None
