# backend/services/crawler/parsers/sku_hints/case.py
from __future__ import annotations

import re

from ..common import head_before_brackets, normalize_spaces
from ..shared_specs import build_title_desc_texts
from ..shared_specs import extract_limit_hint
from ..shared_specs import extract_model_head
from ..shared_specs import normalized_title_line
from ..shared_specs import strip_leading_bracket_tags as _strip_leading_bracket_tags

_FORM_FACTORS: list[tuple[re.Pattern[str], str, int]] = [ # 主機板尺寸對應規則，依照尺寸由大到小排序以利挑選最大尺寸。
    (re.compile(r"(?<![A-Za-z0-9])E-?ATX(?![A-Za-z0-9])", flags=re.IGNORECASE), "E-ATX", 4),
    (re.compile(r"(?<![A-Za-z0-9])(?<![Ee]-)(?<![Mm]-)ATX(?![A-Za-z0-9])", flags=re.IGNORECASE), "ATX", 3),
    (re.compile(r"(?<![A-Za-z0-9])M-?ATX(?![A-Za-z0-9])|Micro-ATX", flags=re.IGNORECASE), "Micro-ATX", 2),
    (re.compile(r"(?<![A-Za-z0-9])Mini-ITX(?![A-Za-z0-9])|(?<![A-Za-z0-9])ITX(?![A-Za-z0-9])", flags=re.IGNORECASE), "Mini-ITX", 1),
]

_GPU_LABEL_RE = re.compile(r"(?:(顯卡長|卡長)|(?<![\u4e00-\u9fff])卡)\s*[:：]?\s*", flags=re.IGNORECASE) # GPU 最長支援長度標籤
_CPU_LABEL_RE = re.compile(r"(CPU散熱器高|CPU高|U高)\s*[:：]?\s*", flags=re.IGNORECASE) # CPU 散熱器最高支援高度標籤

_RADIATOR_SIZE_RE = re.compile(r"(?<!\d)(120|240|280|360|420)(?!\d)") # 水冷排尺寸（mm）
_DIMENSIONS_RE = re.compile( # 機殼尺寸（寬x高x深）
    r"尺寸[:：]?\s*([0-9]+(?:\.[0-9]+)?)\s*[x×*]\s*([0-9]+(?:\.[0-9]+)?)\s*[x×*]\s*([0-9]+(?:\.[0-9]+)?)",
    flags=re.IGNORECASE,
)

_SIDE_TG_RE = re.compile(r"(玻璃|鋼化玻璃|TG|透側)", flags=re.IGNORECASE) # 透側面板提示
_SIDE_ACRYLIC_RE = re.compile(r"(壓克力|Acrylic)", flags=re.IGNORECASE) # 壓克力面板提示
_SIDE_SOLID_RE = re.compile(r"(無側透|鐵側板|金屬側板|網孔|Solid|靜音側板|隔音側板|靜音)", flags=re.IGNORECASE) # 實心面板提示

_DRIVE_BAY_RE = re.compile(r"(5\.25|3\.5|2\.5)\s*[*x×]\s*(\d+)", flags=re.IGNORECASE) # 硬碟空間數量標籤
_DRIVE_BAY_SSD_RE = re.compile(r"(?<![A-Za-z0-9])SSD\s*[*x×]\s*(\d+)", flags=re.IGNORECASE)
_DRIVE_BAY_HDD_RE = re.compile(r"(?<![A-Za-z0-9])HDD\s*[*x×]\s*(\d+)", flags=re.IGNORECASE)
_DRIVE_HOTSWAP_RE = re.compile(r"(?<!\d)(\d+)\s*[*x×]\s*硬碟熱插拔")

_BUNDLE_RE = re.compile(r"(大全配|套裝|組合|bundle)", flags=re.IGNORECASE) # 套裝提示
_LIMIT_RE = re.compile(r"(限組裝|限購|限量|客訂)", flags=re.IGNORECASE) # 限制購買提示
_ACCESSORY_RE = re.compile(r"(配件|支架|扣具)", flags=re.IGNORECASE) # 配件提示
_CASE_LIKE_RE = re.compile( # 機殼相關提示詞
    r"(?i)(顯卡長|卡長|CPU高|U高|水冷|風扇支援|前I/O|尺寸|"
    r"E-?ATX|ATX|M-?ATX|Micro-ATX|Mini-ITX|ITX|玻璃|透側|機殼|電源)"
)
_BRAND_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{1,}") # 品牌可能的字元組合

_PSU_INCLUDED_RE = re.compile(
    r"(含電源|機殼\+電源|內附\s*\d{2,4}\s*W?\s*(?:\S+\s*){0,2}電源)",
    flags=re.IGNORECASE,
)
_PSU_WATT_RE = re.compile(r"(\d{2,4})\s*W", flags=re.IGNORECASE) # 電源瓦數標籤

_MODEL_BUNDLE_SPLIT_RE = re.compile(r"\s+[+＋]\s+") # 型號與套裝配件之間的分隔符號
_MODEL_TRAILING_SPEC_RE = re.compile( # 型號後方可能出現的規格描述，要去除以免干擾型號判斷。
    r"(?:\s*(?:顯卡長|卡長|卡|CPU高|U高)(?:\s*\d+(?:\.\d+)?(?:\([^)]*\))?)?)+\s*$",
    flags=re.IGNORECASE,
)


def _extract_model_hint(text: str) -> str | None:
    head = extract_model_head(
        text,
        strip_bracket_tags=True,
        bundle_split_re=_MODEL_BUNDLE_SPLIT_RE,
        clean_pattern=_MODEL_TRAILING_SPEC_RE,
    )
    return head or None


def _extract_brand(text: str) -> str | None:
    clean = _strip_leading_bracket_tags(text)
    cjk_m = re.match(r"^([\u4e00-\u9fff]{1,20})", clean or "")
    if cjk_m:
        return cjk_m.group(1)
    for m in _BRAND_TOKEN_RE.finditer(clean or ""):
        return m.group(0).upper()
    return None


def _pick_max_form_factor(values: set[str]) -> str | None:
    if not values:
        return None
    rank = {label: score for _pat, label, score in _FORM_FACTORS}
    return max(values, key=lambda v: rank.get(v, 0))


def _collect_form_factors(text: str) -> set[str]:
    found: set[str] = set()
    for pat, label, _score in _FORM_FACTORS:
        if pat.search(text or ""):
            found.add(label)
    return found


def _extract_mb_form_factor(lines: list[str]) -> str | None:
    found: set[str] = set()
    for line in lines:
        factors = _collect_form_factors(line)
        if ("電供" in line or "電源" in line) and not factors:
            continue
        found |= factors
    return _pick_max_form_factor(found)


def _to_mm(value: float, unit: str | None) -> int:
    if unit == "mm":
        return int(round(value))
    if unit == "cm":
        return int(round(value * 10))
    if value <= 80:
        return int(round(value * 10))
    return int(round(value))


def _extract_labeled_length_mm(text: str, label_re: re.Pattern[str]) -> int | None:
    m = label_re.search(text or "")
    if not m:
        return None
    tail = (text or "")[m.end():]
    segment = re.split(r"[／/|｜]", tail, 1)[0]
    nums = [float(n) for n in re.findall(r"\d+(?:\.\d+)?", segment)]
    if not nums:
        return None
    unit = "mm" if re.search(r"mm", segment, flags=re.IGNORECASE) else "cm" if re.search(r"cm", segment, flags=re.IGNORECASE) else None
    return _to_mm(max(nums), unit)

def _extract_labeled_length_from_lines(lines: list[str], label_re: re.Pattern[str]) -> int | None:
    for line in lines:
        val = _extract_labeled_length_mm(line, label_re)
        if val is not None:
            return val
    return None


def _extract_radiator_support_with_seen(lines: list[str]) -> tuple[list[int] | None, bool]:
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


def _extract_dimensions_mm(lines: list[str]) -> list[int] | None:
    for line in lines:
        if "尺寸" not in line:
            continue
        m = _DIMENSIONS_RE.search(line)
        if not m:
            continue
        raw = m.group(0)
        if "/" in raw or "(" in raw or ")" in raw:
            return None
        unit = "mm" if re.search(r"mm", line, flags=re.IGNORECASE) else "cm" if re.search(r"cm", line, flags=re.IGNORECASE) else "cm"
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


def _extract_side_panel(text: str) -> str | None:
    if _SIDE_TG_RE.search(text or ""):
        return "TG"
    if _SIDE_ACRYLIC_RE.search(text or ""):
        return "Acrylic"
    if _SIDE_SOLID_RE.search(text or ""):
        return "Solid"
    return None


def _extract_drive_bays(lines: list[str]) -> dict[str, int] | None:
    for line in lines:
        # 允許 title/desc 常見寫法：硬碟位、SSD*2、熱插拔等
        if not any(k in line for k in ("硬碟空間", "硬碟位", "SSD", "HDD", "熱插拔")):
            continue
        content = line
        if "：" in content:
            content = content.split("：", 1)[1]
        elif ":" in content:
            content = content.split(":", 1)[1]
        # 拿掉括號內容（常見 2.5/3.5 吋註記、型號括號），避免過度保守直接 return None
        content = re.sub(r"\([^)]*\)", "", content)
        if re.search(r"\bor\b|或", content, flags=re.IGNORECASE):
            return None

        result: dict[str, int] = {}

        # 1) 直接尺寸：3.5*9 / 2.5*2 / 5.25*1 ...
        for size, count in _DRIVE_BAY_RE.findall(content):
            n = int(count)
            prev = result.get(size)
            result[size] = n if prev is None else max(prev, n)

        # 2) SSD*2 / HDD*4
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

        # 3) 8*硬碟熱插拔(...)：通常 tray 可兼容 2.5/3.5，先保守記為 3.5=8
        m = _DRIVE_HOTSWAP_RE.search(content)
        if m:
            n = int(m.group(1))
            prev = result.get("3.5")
            result["3.5"] = n if prev is None else max(prev, n)

        if result:
            return result
    return None


def _collect_text_lines(lines: list[str], keyword: str) -> str | None:
    hits = [normalize_spaces(line) for line in lines if keyword in line]
    if not hits:
        return None
    return " / ".join(hits)

def _normalize_fan_support(text: str | None) -> str | None:
    if not text:
        return text
    text = re.sub(r"(?<!\d)12\*14\*(\d+)", r"12/14*\1", text)
    text = re.sub(r"(?<!\d)14\*12\*(\d+)", r"12/14*\1", text)
    return text


def _extract_psu_included(lines: list[str]) -> bool | None:
    for line in lines:
        if _PSU_INCLUDED_RE.search(line):
            return True
    return None


def _extract_psu_watt(lines: list[str]) -> int | None:
    for line in lines:
        if "電源" not in line and not _PSU_INCLUDED_RE.search(line):
            continue
        watts = [int(m.group(1)) for m in _PSU_WATT_RE.finditer(line)]
        if watts:
            return max(watts)
    return None


def extract_case_sku_hint(title: str) -> str | None:
    line = normalized_title_line(title)
    return _extract_model_hint(_strip_leading_bracket_tags(line))


def extract_case_hints(title: str, desc_lines: list[str] | None) -> tuple[str | None, dict[str, object]]:
    """
    回傳 (sku_hint, extra)；extra keys 固定且必須存在：
    brand_hint, model_hint, mb_form_factor_support_hint, gpu_max_length_mm_hint,
    cpu_cooler_max_height_mm_hint, radiator_support_mm_hint, dimensions_mm_hint,
    side_panel_hint, drive_bays_hint, included_fans_hint, fan_support_hint,
    front_io_hint, psu_included_hint, psu_watt_w_hint, limit_hint, is_bundle, is_accessory
    """
    text = title or ""
    line, lines, _texts = build_title_desc_texts(text, desc_lines)
    head = head_before_brackets(line)

    clean_line = _strip_leading_bracket_tags(line)
    brand_hint = _extract_brand(head or clean_line)
    model_hint = _extract_model_hint(clean_line)
    sku_hint = model_hint

    mb_form_factor_support_hint = _extract_mb_form_factor(lines) or _extract_mb_form_factor([line])
    gpu_title_value = _extract_labeled_length_mm(line, _GPU_LABEL_RE)
    gpu_desc_value = _extract_labeled_length_from_lines(lines, _GPU_LABEL_RE)
    if gpu_title_value is not None and gpu_desc_value is not None:
        gpu_max_length_mm_hint = max(gpu_title_value, gpu_desc_value)
    else:
        gpu_max_length_mm_hint = gpu_title_value if gpu_title_value is not None else gpu_desc_value
    cpu_title_value = _extract_labeled_length_mm(line, _CPU_LABEL_RE)
    cpu_desc_value = _extract_labeled_length_from_lines(lines, _CPU_LABEL_RE)
    if cpu_title_value is not None and cpu_desc_value is not None:
        cpu_cooler_max_height_mm_hint = max(cpu_title_value, cpu_desc_value)
    else:
        cpu_cooler_max_height_mm_hint = cpu_title_value if cpu_title_value is not None else cpu_desc_value

    radiator_support_mm_hint, seen_support = _extract_radiator_support_with_seen(lines)
    if radiator_support_mm_hint is None and not seen_support:
        radiator_support_mm_hint, _seen = _extract_radiator_support_with_seen([line])

    dimensions_mm_hint = _extract_dimensions_mm(lines)
    if dimensions_mm_hint is None:
        dimensions_mm_hint = _extract_dimensions_mm([line])

    side_panel_hint = _extract_side_panel(" ".join(lines)) or _extract_side_panel(line)

    drive_bays_hint = _extract_drive_bays(lines)
    if drive_bays_hint is None:
        drive_bays_hint = _extract_drive_bays([line])

    included_fans_hint = _collect_text_lines(lines, "內附風扇") or _collect_text_lines([line], "內附風扇")
    fan_support_hint = _collect_text_lines(lines, "風扇支援") or _collect_text_lines([line], "風扇支援")
    front_io_hint = _collect_text_lines(lines, "前I/O") or _collect_text_lines([line], "前I/O")
    fan_support_hint = _normalize_fan_support(fan_support_hint)

    psu_included_hint = _extract_psu_included(lines) or _extract_psu_included([line])
    psu_watt_w_hint = _extract_psu_watt(lines) or _extract_psu_watt([line])
    if psu_watt_w_hint is not None and psu_included_hint is None:
        psu_included_hint = True

    limit_hint = extract_limit_hint(lines or [line], _LIMIT_RE)

    bundle_blob = " ".join([line] + lines)  # 一定包含 title + desc
    is_bundle = bool(
        _BUNDLE_RE.search(head)
        or _PSU_INCLUDED_RE.search(bundle_blob)
        or _MODEL_BUNDLE_SPLIT_RE.search(line)
    )

    accessory_text = head_before_brackets(clean_line) or clean_line
    blob = " ".join([line] + lines)

    # 只有「出現配件關鍵字」且「整體不像機殼本體」才判定 accessory
    is_accessory = True if (_ACCESSORY_RE.search(accessory_text) and not _CASE_LIKE_RE.search(blob)) else None

    # sanity-check examples fixed here:
    # - "M-ATX" / "E-ATX" no longer back-matches ATX.
    # - "卡35.6/顯卡長36.1" keeps the larger, more realistic value.
    # - "PCIe4.0/5.0 顯示卡延長線" avoids the bare "卡" label match.
    extra = {
        "brand_hint": brand_hint,
        "model_hint": model_hint,
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
    return sku_hint, extra
