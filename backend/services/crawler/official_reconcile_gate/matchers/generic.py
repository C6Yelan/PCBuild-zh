# backend/services/crawler/official_reconcile_gate/matchers/generic.py
"""Generic matcher for T6 pilot flow."""

from __future__ import annotations

import re

from ..types import ListingInput, MatchDecisionWithOfficial, OfficialCandidate, OfficialSignals

_RE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_IDENTIFIER_KEYS = ("mpn", "gtin", "gtin8", "gtin12", "gtin13", "gtin14")


class GenericMatcher:
    category = "GENERIC"

    def score(
        self,
        item: ListingInput,
        candidate: OfficialCandidate,
        signals: OfficialSignals,
    ) -> float:
        retail_tokens = _tokenize(_retail_text(item))
        official_tokens = _tokenize(_official_text(signals))
        matched_tokens = sorted(retail_tokens & official_tokens)
        return len(matched_tokens) / max(1, len(retail_tokens))

    def decide(
        self,
        item: ListingInput,
        candidate: OfficialCandidate,
        signals: OfficialSignals,
        score: float,
    ) -> MatchDecisionWithOfficial:
        retail_tokens = _tokenize(_retail_text(item))
        official_tokens = _tokenize(_official_text(signals))
        matched_tokens = sorted(retail_tokens & official_tokens)
        anchor_ok, anchor_info = self.anchor_check(item, signals)

        if _has_identifier_exact(item.get("identifiers"), signals.get("identifiers")):
            status = "matched"
            confidence = 1.0
            reason_code = "IDENTIFIER_EXACT"
            notes = "matched by exact identifier (mpn/gtin)"
        else:
            confidence = max(0.0, min(1.0, float(score)))
            if confidence >= 0.60:
                status = "matched"
                reason_code = "TOKEN_OVERLAP_HIGH"
                notes = "matched by token overlap threshold"
            elif confidence >= 0.35:
                status = "ambiguous"
                reason_code = "TOKEN_OVERLAP_MID"
                notes = "ambiguous token overlap range"
            else:
                status = "unmatched"
                reason_code = "TOKEN_OVERLAP_LOW"
                notes = "insufficient token overlap"

        evidence: dict[str, object] = {
            "retail_tokens": sorted(retail_tokens),
            "official_tokens": sorted(official_tokens),
            "matched_tokens": matched_tokens,
            "notes": notes,
            "anchor_check": {"pass": anchor_ok, **anchor_info},
        }
        return {
            "status": status,
            "confidence": confidence,
            "reason_code": reason_code,
            "evidence": evidence,
            "official_source": candidate["official_source"],
            "official_url": signals["official_url"],
        }

    def safe_fields(self) -> set[str]:
        return set()

    def anchor_check(
        self,
        item: ListingInput,
        signals: OfficialSignals,
    ) -> tuple[bool, dict[str, object]]:
        return True, {"note": "generic matcher"}


def _retail_text(item: ListingInput) -> str:
    title = item.get("title", "")
    model_hint = item.get("model_hint", "")
    if model_hint:
        return f"{title} {model_hint}"
    return title


def _official_text(signals: OfficialSignals) -> str:
    product_title = signals.get("product_title") or ""
    model = signals.get("model") or ""
    if model:
        return f"{product_title} {model}"
    return product_title


def _tokenize(text: str) -> set[str]:
    return {m.group(0).upper() for m in _RE_TOKEN.finditer(text)}


def _has_identifier_exact(
    retail_identifiers: dict[str, str] | None,
    official_identifiers: dict[str, str] | None,
) -> bool:
    if not retail_identifiers or not official_identifiers:
        return False

    for key in _IDENTIFIER_KEYS:
        retail_value = _normalize_identifier_value(retail_identifiers.get(key))
        official_value = _normalize_identifier_value(official_identifiers.get(key))
        if retail_value and official_value and retail_value == official_value:
            return True
    return False


def _normalize_identifier_value(value: str | None) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()
