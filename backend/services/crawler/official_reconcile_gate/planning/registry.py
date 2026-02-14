# backend/services/crawler/official_reconcile_gate/planning/registry.py
from __future__ import annotations

import json
import re
from pathlib import Path

from .types import BrandRegistryEntry, OfficialRegistry

_SPACE_RE = re.compile(r"\s+", flags=re.UNICODE)


def normalize_brand_token(value: str) -> str:
    text = (value or "").replace("\u3000", " ").strip()
    if not text:
        return ""
    return _SPACE_RE.sub(" ", text).upper()


def resolve_brand_key(registry: OfficialRegistry, raw: str) -> str | None:
    return registry.alias_map.get(normalize_brand_token(raw))


def get_allowed_domains(registry: OfficialRegistry, brand_key: str | None) -> list[str]:
    if not brand_key:
        return []
    for entry in registry.brands:
        if entry.brand_key == brand_key:
            return list(entry.allowed_domains)
    return []


def load_official_registry(path: str | Path) -> OfficialRegistry:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    if not isinstance(payload, dict):
        raise ValueError("registry JSON must be an object")

    version = payload.get("version")
    if not isinstance(version, int):
        raise ValueError("registry.version must be int")

    raw_brands = payload.get("brands")
    if not isinstance(raw_brands, list):
        raise ValueError("registry.brands must be list")

    entries: list[BrandRegistryEntry] = []
    alias_map: dict[str, str] = {}

    for idx, row in enumerate(raw_brands):
        where = f"brands[{idx}]"
        if not isinstance(row, dict):
            raise ValueError(f"{where} must be object")

        raw_key = row.get("brand_key")
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise ValueError(f"{where}.brand_key must be non-empty string")
        brand_key = raw_key.strip().lower()

        aliases_obj = row.get("brand_aliases", [])
        if not isinstance(aliases_obj, list):
            raise ValueError(f"{where}.brand_aliases must be list")
        brand_aliases = [a.strip() for a in aliases_obj if isinstance(a, str) and a.strip()]

        domains_obj = row.get("allowed_domains", [])
        if not isinstance(domains_obj, list):
            raise ValueError(f"{where}.allowed_domains must be list")
        allowed_domains = [d.strip() for d in domains_obj if isinstance(d, str) and d.strip()]

        entry = BrandRegistryEntry(
            brand_key=brand_key,
            brand_aliases=brand_aliases,
            allowed_domains=allowed_domains,
        )
        entries.append(entry)

        for raw_alias in [brand_key, *brand_aliases]:
            token = normalize_brand_token(raw_alias)
            if token and token not in alias_map:
                alias_map[token] = brand_key

    return OfficialRegistry(version=version, brands=entries, alias_map=alias_map)
