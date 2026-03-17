from __future__ import annotations

import re

from ..common import head_before_brackets, normalize_spaces
from ..shared_specs import extract_limit_hint, normalize_length_mm

_FORM_FACTORS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"(?<![A-Za-z0-9])E-?ATX(?![A-Za-z0-9])", flags=re.IGNORECASE), "E-ATX", 4),
    (re.compile(r"(?<![A-Za-z0-9])(?<![Ee]-)(?<![Mm]-)ATX(?![A-Za-z0-9])", flags=re.IGNORECASE), "ATX", 3),
    (re.compile(r"(?<![A-Za-z0-9])M-?ATX(?![A-Za-z0-9])|Micro-ATX", flags=re.IGNORECASE), "Micro-ATX", 2),
    (re.compile(r"(?<![A-Za-z0-9])Mini-ITX(?![A-Za-z0-9])|(?<![A-Za-z0-9])ITX(?![A-Za-z0-9])", flags=re.IGNORECASE), "Mini-ITX", 1),
]
_GPU_LABEL_RE = re.compile(r"(?:(顯卡長|卡長)|(?<![\u4e00-\u9fff])卡)\s*[:：]?\s*", flags=re.IGNORECASE)
_CPU_LABEL_RE = re.compile(r"(CPU散熱器高|CPU高|U高)\s*[:：]?\s*", flags=re.IGNORECASE)
_LENGTH_SPLIT_RE = re.compile(r"[／/|｜]")
_RADIATOR_SIZE_RE = re.compile(r"(?<!\d)(120|240|280|360|420)(?!\d)")
_DIMENSIONS_RE = re.compile(
    r"尺寸[:：]?\s*([0-9]+(?:\.[0-9]+)?)\s*[x×*]\s*([0-9]+(?:\.[0-9]+)?)\s*[x×*]\s*([0-9]+(?:\.[0-9]+)?)",
    flags=re.IGNORECASE,
)
_SIDE_TG_RE = re.compile(r"(玻璃|鋼化玻璃|TG|透側)", flags=re.IGNORECASE)
_SIDE_ACRYLIC_RE = re.compile(r"(壓克力|Acrylic)", flags=re.IGNORECASE)
_SIDE_SOLID_RE = re.compile(r"(無側透|鐵側板|金屬側板|網孔|Solid|靜音側板|隔音側板|靜音)", flags=re.IGNORECASE)
_DRIVE_BAY_RE = re.compile(r"(5\.25|3\.5|2\.5)\s*[*x×]\s*(\d+)", flags=re.IGNORECASE)
_DRIVE_BAY_SSD_RE = re.compile(r"(?<![A-Za-z0-9])SSD\s*[*x×]\s*(\d+)", flags=re.IGNORECASE)
_DRIVE_BAY_HDD_RE = re.compile(r"(?<![A-Za-z0-9])HDD\s*[*x×]\s*(\d+)", flags=re.IGNORECASE)
_DRIVE_HOTSWAP_RE = re.compile(r"(?<!\d)(\d+)\s*[*x×]\s*硬碟熱插拔")
_BUNDLE_RE = re.compile(r"(大全配|套裝|組合|bundle)", flags=re.IGNORECASE)
_LIMIT_RE = re.compile(r"(限組裝|限購|限量|客訂)", flags=re.IGNORECASE)
_ACCESSORY_RE = re.compile(r"(配件|支架|扣具)", flags=re.IGNORECASE)
_CASE_LIKE_RE = re.compile(
    r"(?i)(顯卡長|卡長|CPU高|U高|水冷|風扇支援|前I/O|尺寸|"
    r"E-?ATX|ATX|M-?ATX|Micro-ATX|Mini-ITX|ITX|玻璃|透側|機殼|電源)"
)
_PSU_INCLUDED_RE = re.compile(
    r"(含電源|機殼\+電源|內附\s*\d{2,4}\s*W?\s*(?:\S+\s*){0,2}電源)",
    flags=re.IGNORECASE,
)
_PSU_WATT_RE = re.compile(r"(\d{2,4})\s*W", flags=re.IGNORECASE)
_MODEL_BUNDLE_SPLIT_RE = re.compile(r"\s+[+＋]\s+")


def pick_case_form_factor(values: set[str]) -> str | None:
    if not values:
        return None
    rank = {label: score for _pat, label, score in _FORM_FACTORS}
    return max(values, key=lambda value: rank.get(value, 0))


def collect_case_form_factors(text: str) -> set[str]:
    found: set[str] = set()
    for pat, label, _score in _FORM_FACTORS:
        if pat.search(text or ""):
            found.add(label)
    return found


def extract_case_mb_form_factor(lines: list[str]) -> str | None:
    found: set[str] = set()
    for line in lines:
        factors = collect_case_form_factors(line)
        if ("電供" in line or "電源" in line) and not factors:
            continue
        found |= factors
    return pick_case_form_factor(found)


def extract_case_radiator_support(lines: list[str]) -> tuple[list[int] | None, bool]:
    sizes: set[int] = set()
    seen_support = False
    for line in lines:
        if "水冷" not in line:
            continue
        seen_support = True
        for m in _RADIATOR_SIZE_RE.finditer(line):
            sizes.add(int(m.group(1)))
    if sizes:
        return sorted(sizes), True
    return None, seen_support


def extract_case_dimensions_mm(lines: list[str]) -> list[int] | None:
    for line in lines:
        if "尺寸" not in line:
            continue
        m = _DIMENSIONS_RE.search(line)
        if not m:
            continue
        raw = m.group(0)
        if "/" in raw or "(" in raw or ")" in raw:
            return None
        unit = "mm" if re.search(r"mm", line, flags=re.IGNORECASE) else "cm"
        values = [float(m.group(i)) for i in range(1, 4)]
        if unit == "cm":
            if any(v > 100 for v in values):
                return None
            dims = [int(round(v * 10)) for v in values]
        else:
            dims = [int(round(v)) for v in values]
        if any(v > 1200 for v in dims):
            return None
        return dims
    return None


def extract_case_side_panel(text: str) -> str | None:
    if _SIDE_TG_RE.search(text or ""):
        return "TG"
    if _SIDE_ACRYLIC_RE.search(text or ""):
        return "Acrylic"
    if _SIDE_SOLID_RE.search(text or ""):
        return "Solid"
    return None


def extract_case_drive_bays(lines: list[str]) -> dict[str, int] | None:
    for line in lines:
        if not any(k in line for k in ("硬碟空間", "硬碟位", "SSD", "HDD", "熱插拔")):
            continue
        content = line
        if "：" in content:
            content = content.split("：", 1)[1]
        elif ":" in content:
            content = content.split(":", 1)[1]
        content = re.sub(r"\([^)]*\)", "", content)
        if re.search(r"\bor\b|或", content, flags=re.IGNORECASE):
            return None
        result: dict[str, int] = {}
        for size, count in _DRIVE_BAY_RE.findall(content):
            n = int(count)
            prev = result.get(size)
            result[size] = n if prev is None else max(prev, n)
        m = _DRIVE_BAY_SSD_RE.search(content)
        if m:
            n = int(m.group(1))
            prev = result.get("2.5")
            result["2.5"] = n if prev is None else max(prev, n)
        m = _DRIVE_BAY_HDD_RE.search(content)
        if m:
            n = int(m.group(1))
            prev = result.get("3.5")
            result["3.5"] = n if prev is None else max(prev, n)
        m = _DRIVE_HOTSWAP_RE.search(content)
        if m:
            n = int(m.group(1))
            prev = result.get("3.5")
            result["3.5"] = n if prev is None else max(prev, n)
        if result:
            return result
    return None


def collect_case_text_lines(lines: list[str], keyword: str) -> str | None:
    hits = [normalize_spaces(line) for line in lines if keyword in line]
    if not hits:
        return None
    return " / ".join(hits)


def normalize_case_fan_support(text: str | None) -> str | None:
    if not text:
        return text
    text = re.sub(r"(?<!\d)12\*14\*(\d+)", r"12/14*\1", text)
    text = re.sub(r"(?<!\d)14\*12\*(\d+)", r"12/14*\1", text)
    return text


def extract_case_psu_included(lines: list[str]) -> bool | None:
    for line in lines:
        if _PSU_INCLUDED_RE.search(line):
            return True
    return None


def extract_case_psu_watt(lines: list[str]) -> int | None:
    for line in lines:
        if "電源" not in line and not _PSU_INCLUDED_RE.search(line):
            continue
        watts = [int(m.group(1)) for m in _PSU_WATT_RE.finditer(line)]
        if watts:
            return max(watts)
    return None


def extract_case_labeled_length_mm(
    text: str,
    label_re: re.Pattern[str],
    *,
    split_re: re.Pattern[str] | None = _LENGTH_SPLIT_RE,
    assume_cm_threshold: float = 80,
) -> int | None:
    m = label_re.search(text or "")
    if not m:
        return None
    tail = (text or "")[m.end() :]
    segment = split_re.split(tail, 1)[0] if split_re is not None else tail
    nums = [float(n) for n in re.findall(r"\d+(?:\.\d+)?", segment)]
    if not nums:
        return None
    unit = (
        "mm"
        if re.search(r"mm", segment, flags=re.IGNORECASE)
        else "cm"
        if re.search(r"cm|公分", segment, flags=re.IGNORECASE)
        else None
    )
    return normalize_length_mm(max(nums), unit, assume_cm_threshold=assume_cm_threshold)


def extract_case_labeled_length_from_lines(
    lines: list[str],
    label_re: re.Pattern[str],
    *,
    split_re: re.Pattern[str] | None = _LENGTH_SPLIT_RE,
    assume_cm_threshold: float = 80,
) -> int | None:
    for line in lines:
        value = extract_case_labeled_length_mm(
            line,
            label_re,
            split_re=split_re,
            assume_cm_threshold=assume_cm_threshold,
        )
        if value is not None:
            return value
    return None


def extract_case_spec_hints(
    *,
    line: str,
    lines: list[str],
    head: str,
    clean_line: str,
) -> dict[str, object]:
    mb_form_factor_support_hint = extract_case_mb_form_factor(lines) or extract_case_mb_form_factor([line])
    gpu_title_value = extract_case_labeled_length_mm(line, _GPU_LABEL_RE)
    gpu_desc_value = extract_case_labeled_length_from_lines(lines, _GPU_LABEL_RE)
    if gpu_title_value is not None and gpu_desc_value is not None:
        gpu_max_length_mm_hint = max(gpu_title_value, gpu_desc_value)
    else:
        gpu_max_length_mm_hint = gpu_title_value if gpu_title_value is not None else gpu_desc_value

    cpu_title_value = extract_case_labeled_length_mm(line, _CPU_LABEL_RE)
    cpu_desc_value = extract_case_labeled_length_from_lines(lines, _CPU_LABEL_RE)
    if cpu_title_value is not None and cpu_desc_value is not None:
        cpu_cooler_max_height_mm_hint = max(cpu_title_value, cpu_desc_value)
    else:
        cpu_cooler_max_height_mm_hint = cpu_title_value if cpu_title_value is not None else cpu_desc_value

    radiator_support_mm_hint, seen_support = extract_case_radiator_support(lines)
    if radiator_support_mm_hint is None and not seen_support:
        radiator_support_mm_hint, _seen = extract_case_radiator_support([line])

    dimensions_mm_hint = extract_case_dimensions_mm(lines)
    if dimensions_mm_hint is None:
        dimensions_mm_hint = extract_case_dimensions_mm([line])

    side_panel_hint = extract_case_side_panel(" ".join(lines)) or extract_case_side_panel(line)
    drive_bays_hint = extract_case_drive_bays(lines) or extract_case_drive_bays([line])
    included_fans_hint = collect_case_text_lines(lines, "內附風扇") or collect_case_text_lines([line], "內附風扇")
    fan_support_hint = collect_case_text_lines(lines, "風扇支援") or collect_case_text_lines([line], "風扇支援")
    front_io_hint = collect_case_text_lines(lines, "前I/O") or collect_case_text_lines([line], "前I/O")
    fan_support_hint = normalize_case_fan_support(fan_support_hint)

    psu_included_hint = extract_case_psu_included(lines) or extract_case_psu_included([line])
    psu_watt_w_hint = extract_case_psu_watt(lines) or extract_case_psu_watt([line])
    if psu_watt_w_hint is not None and psu_included_hint is None:
        psu_included_hint = True

    limit_hint = extract_limit_hint(lines or [line], _LIMIT_RE)
    bundle_blob = " ".join([line] + lines)
    is_bundle = bool(
        _BUNDLE_RE.search(head)
        or _PSU_INCLUDED_RE.search(bundle_blob)
        or _MODEL_BUNDLE_SPLIT_RE.search(line)
    )

    accessory_text = head_before_brackets(clean_line) or clean_line
    blob = " ".join([line] + lines)
    is_accessory = True if (_ACCESSORY_RE.search(accessory_text) and not _CASE_LIKE_RE.search(blob)) else None

    return {
        "mb_form_factor_support_hint": mb_form_factor_support_hint,
        "gpu_max_length_mm_hint": gpu_max_length_mm_hint,
        "cpu_cooler_max_height_mm_hint": cpu_cooler_max_height_mm_hint,
        "radiator_support_mm_hint": radiator_support_mm_hint,
        "dimensions_mm_hint": dimensions_mm_hint,
        "side_panel_hint": side_panel_hint,
        "drive_bays_hint": drive_bays_hint,
        "included_fans_hint": included_fans_hint,
        "fan_support_hint": fan_support_hint,
        "front_io_hint": front_io_hint,
        "psu_included_hint": psu_included_hint,
        "psu_watt_w_hint": psu_watt_w_hint,
        "limit_hint": limit_hint,
        "is_bundle": is_bundle,
        "is_accessory": is_accessory,
    }
