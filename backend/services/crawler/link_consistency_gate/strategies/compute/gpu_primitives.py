# backend/services/crawler/link_consistency_gate/strategies/compute/gpu_primitives.py
from __future__ import annotations

import re

from ...types import ListingInput, PageSignals
from ..shared_primitives import compose_page_text, normalize_spaces, normalize_upper_pattern_text

_RE_SEP = re.compile(r"[\\/._|,:;+=~\-]+", flags=re.UNICODE)
_RE_BRACKET_SYMBOLS = re.compile(r"[\[\]【】\(\)（）\{\}<>]", flags=re.UNICODE)
_RE_TITLE_PREFIX = re.compile(r"^\s*[【\[]?(?:限搭|搭機價|組裝價|組裝/升級|促銷)[】\]]?\s*", flags=re.UNICODE)
_RE_TITLE_SPLIT = re.compile(r"[／/]", flags=re.UNICODE)
_RE_ALPHA_TO_DIGIT = re.compile(r"(?<=[A-Z])(?=[0-9])", flags=re.UNICODE)
_RE_DIGIT_TO_ALPHA = re.compile(r"(?<=[0-9])(?=[A-Z])", flags=re.UNICODE)
_RE_GEFORCE_GLUE = re.compile(r"GEFORCE(?=RTX|GTX)", flags=re.UNICODE)
_RE_RADEON_GLUE = re.compile(r"RADEON(?=RX)", flags=re.UNICODE)
_RE_ARC_GLUE = re.compile(r"ARC(?=[AB][0-9]{2,3})", flags=re.UNICODE)
_RE_NUM_SUFFIX_GLUE = re.compile(r"([0-9]{3,4})(TI|SUPER|XTX|XT)\b", flags=re.UNICODE)
_RE_TI_SUPER_GLUE = re.compile(r"TI(?=SUPER)", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[A-Z0-9]{2,}", flags=re.UNICODE)

_RE_ID_NVIDIA = re.compile(
    r"(?<![A-Z0-9])(?:GEFORCE\s*)?(RTX|GTX)\s*([0-9]{3,4})(?:\s*(TI))?(?:\s*(SUPER))?(?![A-Z0-9])",
    flags=re.UNICODE,
)
_RE_ID_NVIDIA_GT = re.compile(r"(?<![A-Z0-9])GT(?!X)\s*([0-9]{3,4})(?![A-Z0-9])", flags=re.UNICODE)
_RE_ID_NVIDIA_NSKU = re.compile(r"(?<![A-Z0-9])N\s*([0-9]{3,4})(?![A-Z0-9])", flags=re.UNICODE)
_RE_ID_AMD = re.compile(
    r"(?<![A-Z0-9])(?:RADEON\s*)?RX\s*([0-9]{3,4})(?:\s*(XTX|XT))?(?![A-Z0-9])",
    flags=re.UNICODE,
)
_RE_ID_AMD_R_SERIES = re.compile(r"(?<![A-Z0-9])(?:RADEON\s*)?R\s*([579])\s*([0-9]{3})(?![A-Z0-9])", flags=re.UNICODE)
_RE_ID_AMD_SKU_R_SERIES = re.compile(
    r"(?<![A-Z0-9])[A-Z]{1,4}R\s*([579])\s*([0-9]{3})(?![A-Z0-9])",
    flags=re.UNICODE,
)
_RE_ID_AMD_AI_PRO = re.compile(
    r"(?<![A-Z0-9])(?:RADEON\s*)?(?:AI\s*PRO\s*)?R\s*([0-9]{4})(?![A-Z0-9])",
    flags=re.UNICODE,
)
_RE_ID_INTEL = re.compile(r"(?<![A-Z0-9])ARC\s*([AB])\s*([0-9]{2,3})(?![A-Z0-9])", flags=re.UNICODE)


def normalize_gpu_text(text: str) -> str:
    return normalize_upper_pattern_text(
        text,
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP,
        replacements_before=(
            (_RE_GEFORCE_GLUE, "GEFORCE "),
            (_RE_RADEON_GLUE, "RADEON "),
            (_RE_ARC_GLUE, "ARC "),
            (_RE_NUM_SUFFIX_GLUE, r"\1 \2"),
            (_RE_TI_SUPER_GLUE, "TI "),
        ),
        replacements_after=(
            (_RE_ALPHA_TO_DIGIT, " "),
            (_RE_DIGIT_TO_ALPHA, " "),
        ),
    )


def build_gpu_page_text(signals: PageSignals) -> str:
    return compose_page_text(
        signals.text_hint,
        signals.page_title,
        signals.page_h1,
        signals.canonical_url,
        normalize=normalize_spaces,
    )


def extract_gpu_identities(text: str) -> list[str]:
    normalized = normalize_gpu_text(text)
    out: set[str] = set()

    for match in _RE_ID_NVIDIA.finditer(normalized):
        vendor = match.group(1)
        number = match.group(2)
        ti = match.group(3)
        sup = match.group(4)
        parts = [vendor, number]
        if ti:
            parts.append("TI")
        if sup:
            parts.append("SUPER")
        out.add("".join(parts))

    for match in _RE_ID_NVIDIA_GT.finditer(normalized):
        out.add(f"GT{match.group(1)}")

    for match in _RE_ID_NVIDIA_NSKU.finditer(normalized):
        out.add(f"GT{match.group(1)}")

    for match in _RE_ID_AMD.finditer(normalized):
        number = match.group(1)
        suffix = match.group(2)
        parts = ["RX", number]
        if suffix:
            parts.append(suffix)
        out.add("".join(parts))

    for match in _RE_ID_AMD_R_SERIES.finditer(normalized):
        out.add(f"R{match.group(1)}{match.group(2)}")

    for match in _RE_ID_AMD_SKU_R_SERIES.finditer(normalized):
        out.add(f"R{match.group(1)}{match.group(2)}")

    for match in _RE_ID_AMD_AI_PRO.finditer(normalized):
        out.add(f"R{match.group(1)}")

    for match in _RE_ID_INTEL.finditer(normalized):
        out.add(f"ARC{match.group(1)}{match.group(2)}")

    return sorted(out)


def build_gpu_listing_tokens(model_phrase: str, listing_identities: list[str]) -> list[str]:
    out: set[str] = set(extract_gpu_tokens(model_phrase))
    model_normalized = normalize_gpu_text(model_phrase)
    if model_normalized:
        out.add(model_normalized)
    for identity in listing_identities:
        out.add(identity)
        out.update(identity.split())
    return sorted(out)


def build_gpu_page_tokens(page_text: str, page_identities: list[str]) -> list[str]:
    out: set[str] = set(extract_gpu_tokens(page_text))
    for identity in page_identities:
        out.add(identity)
        out.update(identity.split())
    return sorted(out)


def pick_gpu_model_phrase(listing: ListingInput) -> tuple[str, str]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "extra.model_hint"

    if (listing.sku_hint or "").strip():
        return listing.sku_hint.strip(), "sku_hint"

    return gpu_title_head(listing.title), "title_head"


def gpu_title_head(title: str) -> str:
    line = (title or "").splitlines()[0].strip() if title else ""
    if not line:
        return ""
    line = _RE_TITLE_PREFIX.sub("", line)
    line = normalize_spaces(line)
    if not line:
        return ""
    return _RE_TITLE_SPLIT.split(line, maxsplit=1)[0].strip()


def extract_gpu_tokens(text: str) -> list[str]:
    normalized = normalize_gpu_text(text)
    return sorted(set(_RE_TOKEN.findall(normalized)))
