from __future__ import annotations

import re

from ..shared_specs import normalize_length_mm

FORM_FACTORS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"(?<![A-Za-z0-9])E-?ATX(?![A-Za-z0-9])", flags=re.IGNORECASE), "E-ATX", 4),
    (re.compile(r"(?<![A-Za-z0-9])(?<![Ee]-)(?<![Mm]-)ATX(?![A-Za-z0-9])", flags=re.IGNORECASE), "ATX", 3),
    (re.compile(r"(?<![A-Za-z0-9])M-?ATX(?![A-Za-z0-9])|Micro-ATX", flags=re.IGNORECASE), "Micro-ATX", 2),
    (re.compile(r"(?<![A-Za-z0-9])Mini-ITX(?![A-Za-z0-9])|(?<![A-Za-z0-9])ITX(?![A-Za-z0-9])", flags=re.IGNORECASE), "Mini-ITX", 1),
]
LENGTH_SPLIT_RE = re.compile(r"[／/|｜]")
RADIATOR_SIZE_RE = re.compile(r"(?<!\d)(120|240|280|360|420)(?!\d)")
DIMENSIONS_RE = re.compile(
    r"尺寸[:：]?\s*([0-9]+(?:\.[0-9]+)?)\s*[x×*]\s*([0-9]+(?:\.[0-9]+)?)\s*[x×*]\s*([0-9]+(?:\.[0-9]+)?)",
    flags=re.IGNORECASE,
)


def pick_case_form_factor(values: set[str]) -> str | None:
    if not values:
        return None
    rank = {label: score for _pattern, label, score in FORM_FACTORS}
    return max(values, key=lambda value: rank.get(value, 0))


def collect_case_form_factors(text: str) -> set[str]:
    found: set[str] = set()
    for pattern, label, _score in FORM_FACTORS:
        if pattern.search(text or ""):
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
        for match in RADIATOR_SIZE_RE.finditer(line):
            sizes.add(int(match.group(1)))
    if sizes:
        return sorted(sizes), True
    return None, seen_support


def extract_case_dimensions_mm(lines: list[str]) -> list[int] | None:
    for line in lines:
        if "尺寸" not in line:
            continue
        match = DIMENSIONS_RE.search(line)
        if not match:
            continue
        raw = match.group(0)
        if "/" in raw or "(" in raw or ")" in raw:
            return None
        unit = "mm" if re.search(r"mm", line, flags=re.IGNORECASE) else "cm"
        values = [float(match.group(i)) for i in range(1, 4)]
        if unit == "cm":
            if any(value > 100 for value in values):
                return None
            dims = [int(round(value * 10)) for value in values]
        else:
            dims = [int(round(value)) for value in values]
        if any(value > 1200 for value in dims):
            return None
        return dims
    return None


def extract_case_labeled_length_mm(
    text: str,
    label_re: re.Pattern[str],
    *,
    split_re: re.Pattern[str] | None = LENGTH_SPLIT_RE,
    assume_cm_threshold: float = 80,
) -> int | None:
    match = label_re.search(text or "")
    if not match:
        return None
    tail = (text or "")[match.end() :]
    segment = split_re.split(tail, 1)[0] if split_re is not None else tail
    nums = [float(value) for value in re.findall(r"\d+(?:\.\d+)?", segment)]
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
    split_re: re.Pattern[str] | None = LENGTH_SPLIT_RE,
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


__all__ = [
    "collect_case_form_factors",
    "extract_case_dimensions_mm",
    "extract_case_labeled_length_from_lines",
    "extract_case_labeled_length_mm",
    "extract_case_mb_form_factor",
    "extract_case_radiator_support",
    "pick_case_form_factor",
]
