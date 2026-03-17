from __future__ import annotations

from typing import Any

from .types import LinkCheckReport, ListingInput, MatchDecision, PageSignals


def build_fetch_error_report(
    *,
    listing: ListingInput,
    elapsed_ms: int,
    error_type: str,
    error_message: str,
) -> LinkCheckReport:
    return LinkCheckReport(
        source=listing.source,
        category=listing.category,
        title=listing.title,
        url=listing.url,
        final_url="",
        status="error",
        http_status=None,
        elapsed_ms=elapsed_ms,
        reason_code="FETCH_ERROR",
        evidence={
            "listing_tokens": [],
            "page_tokens": [],
            "matched_tokens": [],
            "notes": ["fetch failed"],
        },
        error={"type": error_type, "message": error_message},
    )


def build_block_page_report(
    *,
    listing: ListingInput,
    final_url: str,
    http_status: int,
    elapsed_ms: int,
    matched_patterns: list[str],
    fetch_meta: Any,
) -> LinkCheckReport:
    evidence: dict[str, Any] = {
        "listing_tokens": [],
        "page_tokens": [],
        "matched_tokens": [],
        "notes": ["block/interstitial page detected"],
        "block_patterns": matched_patterns,
        "fetch_warnings": fetch_meta.warnings,
        "redirect_chain": fetch_meta.redirect_chain,
    }
    return LinkCheckReport(
        source=listing.source,
        category=listing.category,
        title=listing.title,
        url=listing.url,
        final_url=final_url,
        status="error",
        http_status=http_status,
        elapsed_ms=elapsed_ms,
        reason_code="BLOCK_PAGE_DETECTED",
        evidence=evidence,
        error={"type": "BlockedByInterstitial", "message": "block/interstitial page detected"},
    )


def build_extract_error_report(
    *,
    listing: ListingInput,
    final_url: str,
    http_status: int,
    elapsed_ms: int,
    fetch_meta: Any,
    error_type: str,
    error_message: str,
) -> LinkCheckReport:
    return LinkCheckReport(
        source=listing.source,
        category=listing.category,
        title=listing.title,
        url=listing.url,
        final_url=final_url,
        status="error",
        http_status=http_status,
        elapsed_ms=elapsed_ms,
        reason_code="EXTRACT_ERROR",
        evidence={
            "listing_tokens": [],
            "page_tokens": [],
            "matched_tokens": [],
            "notes": ["extract failed"],
            "fetch_warnings": fetch_meta.warnings,
            "redirect_chain": fetch_meta.redirect_chain,
        },
        error={"type": error_type, "message": error_message},
    )


def build_strategy_error_report(
    *,
    listing: ListingInput,
    final_url: str,
    http_status: int,
    elapsed_ms: int,
    fetch_meta: Any,
    error_type: str,
    error_message: str,
) -> LinkCheckReport:
    return LinkCheckReport(
        source=listing.source,
        category=listing.category,
        title=listing.title,
        url=listing.url,
        final_url=final_url,
        status="error",
        http_status=http_status,
        elapsed_ms=elapsed_ms,
        reason_code="STRATEGY_ERROR",
        evidence={
            "listing_tokens": [],
            "page_tokens": [],
            "matched_tokens": [],
            "notes": ["strategy failed"],
            "fetch_warnings": fetch_meta.warnings,
            "redirect_chain": fetch_meta.redirect_chain,
        },
        error={"type": error_type, "message": error_message},
    )


def build_decision_report(
    *,
    listing: ListingInput,
    signals: PageSignals,
    elapsed_ms: int,
    decision: MatchDecision,
    fetch_meta: Any,
) -> LinkCheckReport:
    evidence = dict(decision.evidence or {})
    evidence.setdefault("listing_tokens", [])
    evidence.setdefault("page_tokens", [])
    evidence.setdefault("matched_tokens", [])
    evidence.setdefault("notes", [])
    if fetch_meta.warnings:
        evidence["fetch_warnings"] = fetch_meta.warnings
    if fetch_meta.redirect_chain:
        evidence["redirect_chain"] = fetch_meta.redirect_chain
    return LinkCheckReport(
        source=listing.source,
        category=listing.category,
        title=listing.title,
        url=listing.url,
        final_url=signals.final_url,
        status=decision.status,
        http_status=signals.http_status,
        elapsed_ms=elapsed_ms,
        reason_code=decision.reason_code,
        evidence=evidence,
        error=None,
    )


__all__ = [
    "build_block_page_report",
    "build_decision_report",
    "build_extract_error_report",
    "build_fetch_error_report",
    "build_strategy_error_report",
]
