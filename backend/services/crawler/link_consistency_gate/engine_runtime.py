# backend/services/crawler/link_consistency_gate/engine_runtime.py
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from . import extract, registry
from .engine_reports import (
    build_block_page_report,
    build_decision_report,
    build_extract_error_report,
    build_fetch_error_report,
    build_strategy_error_report,
)
from .types import LinkCheckReport, ListingInput, PageSignals


@dataclass(frozen=True)
class EnginePageContext:
    final_url: str
    http_status: int
    signals: PageSignals
    fetch_meta: Any


def check_listing(engine: Any, listing: ListingInput) -> LinkCheckReport:
    start = time.monotonic()
    page_context = resolve_page_context(engine, listing, start)
    if isinstance(page_context, LinkCheckReport):
        return page_context

    strategy = registry.get_strategy(listing.category)
    try:
        decision = strategy.decide(listing, page_context.signals)
    except Exception as exc:
        return build_strategy_error_report(
            listing=listing,
            final_url=page_context.final_url,
            http_status=page_context.http_status,
            elapsed_ms=elapsed_milliseconds(start),
            fetch_meta=page_context.fetch_meta,
            error_type=type(exc).__name__,
            error_message=engine._one_line_error(exc),
        )

    return build_decision_report(
        listing=listing,
        signals=page_context.signals,
        elapsed_ms=elapsed_milliseconds(start),
        decision=decision,
        fetch_meta=page_context.fetch_meta,
    )


def resolve_page_context(
    engine: Any,
    listing: ListingInput,
    start: float,
) -> EnginePageContext | LinkCheckReport:
    decoded_text = engine._decode_listing_url(listing.url)
    if decoded_text:
        final_url = listing.url
        http_status = 200
        fetch_meta = engine._fetcher.pop_last_meta()
        return EnginePageContext(
            final_url=final_url,
            http_status=http_status,
            fetch_meta=fetch_meta,
            signals=PageSignals(
                final_url=final_url,
                http_status=http_status,
                page_title=None,
                page_h1=None,
                canonical_url=None,
                text_hint=decoded_text,
            ),
        )

    try:
        final_url, http_status, content_bytes, _fetch_elapsed_ms = engine._fetcher.fetch(listing.url)
        fetch_meta = engine._fetcher.pop_last_meta()
    except Exception as exc:
        return build_fetch_error_report(
            listing=listing,
            elapsed_ms=elapsed_milliseconds(start),
            error_type=type(exc).__name__,
            error_message=engine._one_line_error(exc),
        )

    block_report = detect_block_page(
        engine=engine,
        listing=listing,
        final_url=final_url,
        http_status=http_status,
        content_bytes=content_bytes,
        fetch_meta=fetch_meta,
        elapsed_ms=elapsed_milliseconds(start),
    )
    if block_report is not None:
        return block_report

    try:
        signals = extract.extract_page_signals(
            content_bytes,
            final_url=final_url,
            http_status=http_status,
        )
    except Exception as exc:
        return build_extract_error_report(
            listing=listing,
            final_url=final_url,
            http_status=http_status,
            elapsed_ms=elapsed_milliseconds(start),
            fetch_meta=fetch_meta,
            error_type=type(exc).__name__,
            error_message=engine._one_line_error(exc),
        )

    return EnginePageContext(
        final_url=final_url,
        http_status=http_status,
        fetch_meta=fetch_meta,
        signals=signals,
    )


def detect_block_page(
    *,
    engine: Any,
    listing: ListingInput,
    final_url: str,
    http_status: int,
    content_bytes: bytes,
    fetch_meta: Any,
    elapsed_ms: int,
) -> LinkCheckReport | None:
    if not engine._block_regexes:
        return None
    normalized = extract.html_to_text(content_bytes, max_chars=20000)
    matched = [regex.pattern for regex in engine._block_regexes if regex.search(normalized)]
    if not matched:
        return None
    return build_block_page_report(
        listing=listing,
        final_url=final_url,
        http_status=http_status,
        elapsed_ms=elapsed_ms,
        matched_patterns=matched,
        fetch_meta=fetch_meta,
    )


def elapsed_milliseconds(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


__all__ = [
    "EnginePageContext",
    "check_listing",
    "detect_block_page",
    "elapsed_milliseconds",
    "resolve_page_context",
]
