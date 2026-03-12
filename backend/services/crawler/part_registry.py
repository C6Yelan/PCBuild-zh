# backend/services/crawler/part_registry.py
from __future__ import annotations

from backend.services.crawler.registry_primitives import (
    lookup_registry_entry,
    normalize_registry_key,
)


_SOURCE_PART_URLS: dict[str, dict[str, str]] = {
    "coolpc": {
        "cpu": "https://www.coolpc.com.tw/eachview.php?IGrp=4",
        "mb": "https://www.coolpc.com.tw/eachview.php?IGrp=5",
        "ram": "https://www.coolpc.com.tw/eachview.php?IGrp=6",
        "ssd": "https://www.coolpc.com.tw/eachview.php?IGrp=7",
        "hdd": "https://www.coolpc.com.tw/eachview.php?IGrp=8",
        "cooler": "https://www.coolpc.com.tw/eachview.php?IGrp=10",
        "liquid_cooling": "https://www.coolpc.com.tw/eachview.php?IGrp=11",
        "gpu": "https://www.coolpc.com.tw/eachview.php?IGrp=12",
        "case": "https://www.coolpc.com.tw/eachview.php?IGrp=14",
        "psu": "https://www.coolpc.com.tw/eachview.php?IGrp=15",
        "case_fan": "https://www.coolpc.com.tw/eachview.php?IGrp=16",
        "expansion_card": "https://www.coolpc.com.tw/eachview.php?IGrp=27",
    }
}


def get_source_part_urls(source: str) -> dict[str, str]:
    key = normalize_registry_key(source, case="lower")
    urls = lookup_registry_entry(
        _SOURCE_PART_URLS,
        key,
        missing_factory=lambda _key: KeyError(f"unsupported source for incremental refresh: {source!r}"),
    )
    return dict(urls)


def resolve_source_parts(source: str, parts: str | None) -> list[tuple[str, str]]:
    urls = get_source_part_urls(source)
    normalized_parts = normalize_registry_key(parts, case="lower")
    if parts is None or normalized_parts in ("", "all"):
        return [(part, urls[part]) for part in urls.keys()]

    selected: list[str] = []
    allowed = ",".join(urls.keys())
    for raw in parts.split(","):
        token = normalize_registry_key(raw, case="lower", hyphen_to_underscore=True)
        if not token:
            continue
        lookup_registry_entry(
            urls,
            token,
            missing_factory=lambda _key: ValueError(f"unknown part={token!r}, allowed={allowed}"),
        )
        if token not in selected:
            selected.append(token)

    if not selected:
        raise ValueError("parts is empty after parsing")

    return [(part, urls[part]) for part in selected]
