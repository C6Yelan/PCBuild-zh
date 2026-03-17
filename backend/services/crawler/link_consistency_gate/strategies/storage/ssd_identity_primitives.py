# backend/services/crawler/link_consistency_gate/strategies/storage/ssd_identity_primitives.py
from __future__ import annotations

import re

from ...types import ListingInput, PageSignals
from ..shared_primitives import compose_page_text
from .ssd_text_primitives import (
    build_ssd_tokens,
    is_ssd_identity_token,
    is_ssd_sku_like,
    normalize_ssd_phrase,
)

_RE_M2 = re.compile(r"M\s*\.?\s*2", flags=re.UNICODE)
_RE_25 = re.compile(r"2\s*\.?\s*5", flags=re.UNICODE)
_RE_CJK_CHAR = re.compile(r"[\u4e00-\u9fff]", flags=re.UNICODE)
_PROTO_TOKENS = {"SATA", "NVME", "AHCI", "PCIE"}


def build_ssd_page_text(signals: PageSignals) -> str:
    return compose_page_text(signals.page_title, signals.page_h1, signals.text_hint)


def extract_ssd_identity_tokens(tokens: list[str]) -> set[str]:
    return {token for token in tokens if is_ssd_identity_token(token)}


def extract_ssd_spec_tokens(tokens: list[str]) -> set[str]:
    out: set[str] = set()
    for token in tokens:
        if not token:
            continue
        if token in _PROTO_TOKENS or token in {"M2", "2.5"}:
            out.add(token)
            continue
        if re.fullmatch(r"^(\d{1,4})(TB|GB|T|G)$", token, flags=re.UNICODE):
            match = re.fullmatch(r"^(\d{1,4})(TB|GB|T|G)$", token, flags=re.UNICODE)
            if match:
                out.add(f"{int(match.group(1))}{'TB' if match.group(2).upper() in ('T', 'TB') else 'GB'}")
            continue
        if token in build_capacity_tokens(token):
            out.add(token)
    return out


def pick_ssd_model_phrase(listing: ListingInput) -> tuple[str, str]:
    if is_ssd_sku_like(listing.sku_hint):
        return listing.sku_hint, "sku_hint(sku)"
    segment = first_ssd_title_segment(listing.title)
    brand_hint = listing.extra.get("brand_hint")
    if isinstance(brand_hint, str) and brand_hint.strip():
        if segment:
            segment_norm = normalize_ssd_phrase(segment)
            brand_norm = normalize_ssd_phrase(brand_hint)
            if _RE_CJK_CHAR.search(segment):
                return segment, "title_segment(no_brand_for_cjk)"
            if brand_norm and brand_norm in segment_norm:
                return segment, "title_segment(brand_already_in_segment)"
            return f"{brand_hint.strip()} {segment}", "title_segment+brand_hint"
        return brand_hint.strip(), "brand_hint"
    if segment:
        return segment, "title_segment"
    if (listing.title or "").strip():
        return listing.title, "title"
    return listing.sku_hint, "sku_hint"


def build_ssd_listing_tokens(listing: ListingInput) -> list[str]:
    tokens = build_ssd_tokens(
        " ".join(
            [
                listing.sku_hint or "",
                listing.title or "",
                str(listing.extra.get("brand_hint") or ""),
                str(listing.extra.get("model_hint") or ""),
                str(listing.extra.get("interface_hint") or ""),
                str(listing.extra.get("protocol_hint") or ""),
                str(listing.extra.get("form_factor_hint") or ""),
            ]
        )
    )
    return sorted(set(tokens) | extract_ssd_hint_spec_tokens(listing))


def extract_ssd_hint_spec_tokens(listing: ListingInput) -> set[str]:
    out: set[str] = set()
    interface = listing.extra.get("interface_hint")
    protocol = listing.extra.get("protocol_hint")
    form_factor = listing.extra.get("form_factor_hint")
    for value in (interface, protocol):
        if not isinstance(value, str) or not value.strip():
            continue
        normalized = normalize_ssd_phrase(value)
        if "SATA" in normalized:
            out.add("SATA")
        if "NVME" in normalized:
            out.add("NVME")
        if "AHCI" in normalized:
            out.add("AHCI")
        if "PCIE" in normalized:
            out.add("PCIE")
    if isinstance(form_factor, str) and form_factor.strip():
        normalized = normalize_ssd_phrase(form_factor)
        if _RE_M2.search(normalized):
            out.add("M2")
        if _RE_25.search(normalized):
            out.add("2.5")
    return out


def first_ssd_title_segment(title: str) -> str:
    first_line = (title or "").splitlines()[0] if title else ""
    first_line = first_line.strip()
    if not first_line:
        return ""
    segment = re.split(r"[／/]", first_line, maxsplit=1)[0]
    return segment.strip()


def build_capacity_tokens(text: str) -> set[str]:
    return {
        f"{int(match.group(1))}{'TB' if match.group(2).upper() in ('T', 'TB') else 'GB'}"
        for match in re.finditer(r"(?<![A-Z0-9])(\d{1,4})\s*(TB|GB|T|G)(?![A-Z0-9])", normalize_ssd_phrase(text), flags=re.UNICODE)
    }
