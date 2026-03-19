# backend/services/chat/context_pack/retrieval_runtime.py
from __future__ import annotations

from collections.abc import Mapping
from time import perf_counter
from typing import Any
from types import SimpleNamespace

import sqlalchemy as sa
from sqlalchemy.orm import Session

from backend.core.oplog import log_operation
from backend.core.settings import get_settings
from backend.models.crawler_publication import CrawlerPublicationPointer

from .retrieval_contracts import CandidatePart, P1Demand, P1RetrievalResult
from .retrieval_sql import (
    build_category_retrieval_stmt,
    build_retrieval_count_stmt,
    describe_order_by,
    has_search_query,
)
from .typesense_adapter import (
    TypesenseError,
    search_parts as search_parts_typesense,
)


def normalize_retrieval_categories(categories: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for raw in categories:
        value = str(raw).strip()
        if not value or value in seen:
            continue
        deduped.append(value)
        seen.add(value)
    return deduped


def normalize_retrieval_top_k(top_k: int) -> int:
    return max(1, min(int(top_k), 200))


def summarize_retrieval_filters(demand: P1Demand | None) -> str:
    if demand is None:
        return "none"
    parts: list[str] = []
    if demand.budget is not None:
        parts.append(f"budget<={demand.budget}")
    if demand.target_price is not None:
        parts.append(f"target_price={demand.target_price}")
    if demand.min_price is not None:
        parts.append(f"min_price>={demand.min_price}")
    if demand.max_price is not None:
        parts.append(f"max_price<={demand.max_price}")
    return ",".join(parts) if parts else "none"


def detect_pg_trgm_support(db: Session) -> bool:
    info = getattr(db, "info", None)
    if isinstance(info, dict) and "pg_trgm_available" in info:
        return bool(info["pg_trgm_available"])

    bind_getter = getattr(db, "get_bind", None)
    if bind_getter is None:
        return False

    try:
        bind = bind_getter()
    except Exception:
        return False

    if getattr(getattr(bind, "dialect", None), "name", None) != "postgresql":
        return False

    try:
        available = bool(
            db.execute(
                sa.text("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm')")
            ).scalar_one()
        )
    except Exception:
        available = False

    if isinstance(info, dict):
        info["pg_trgm_available"] = available
    return available


def build_candidate_part(row: Mapping[str, Any]) -> CandidatePart:
    return CandidatePart(
        part_id=str(row["part_id"]),
        category=str(row["category"]),
        display_name=str(row["display_name"]),
        key_specs=row["key_specs"] if isinstance(row["key_specs"], dict) else {},
        price=row["price"],
        source=str(row["source"]),
        source_url=str(row["source_url"]),
        run_id=str(row["item_run_id"]),
    )


def fetch_category_candidates(
    db: Session,
    *,
    category: str,
    top_k: int,
    demand: P1Demand | None,
    use_trigram: bool,
) -> tuple[int, list[CandidatePart]]:
    matched_count = int(
        db.execute(
            build_retrieval_count_stmt(
                category=category,
                demand=demand,
            )
        ).scalar_one()
    )
    rows = list(
        db.execute(
            build_category_retrieval_stmt(
                category=category,
                top_k=top_k,
                demand=demand,
                use_trigram=use_trigram,
            )
        ).mappings()
    )
    candidates = [build_candidate_part(row) for row in rows[:top_k]]
    return matched_count, candidates


def retrieve_topk_candidates(
    db: Session,
    *,
    categories: list[str],
    top_k: int,
    demand: P1Demand | None = None,
    env: str = "prod",
) -> P1RetrievalResult:
    normalized_categories = normalize_retrieval_categories(categories)
    normalized_top_k = normalize_retrieval_top_k(top_k)
    if not normalized_categories:
        return P1RetrievalResult(items_by_category={})

    ptr = db.get(CrawlerPublicationPointer, env)
    if ptr is None:
        raise RuntimeError(f"crawler_publication_pointer not found for env={env!r}; please publish first")

    publication_run_id = ptr.run_id
    filters_summary = summarize_retrieval_filters(demand)
    use_fts = has_search_query(demand)
    use_trigram = use_fts and detect_pg_trgm_support(db)
    order_by_summary = describe_order_by(demand, use_trigram=use_trigram)
    query_text = demand.query_text if demand is not None else None
    budget_aware_sorting = bool(
        demand is not None
        and (
            demand.min_price is not None
            or demand.max_price is not None
            or demand.target_price is not None
            or demand.budget is not None
        )
    )
    result: dict[str, list[CandidatePart]] = {}
    try:
        settings = get_settings()
    except Exception:
        settings = SimpleNamespace(typesense_enabled=False)
    typesense_enabled = bool(getattr(settings, "typesense_enabled", False))

    if typesense_enabled:
        try:
            ts_results = search_parts_typesense(
                db,
                settings=settings,
                categories=normalized_categories,
                top_k=normalized_top_k,
                demand=demand,
                env=env,
            )
            for category in normalized_categories:
                started = perf_counter()
                ts_result = ts_results.get(category)
                candidates = ts_result.candidates if ts_result is not None else []
                matched_count = ts_result.found if ts_result is not None else 0
                result[category] = candidates
                latency_ms = int((perf_counter() - started) * 1000)
                log_operation(
                    "p1_retrieval",
                    part_category=category,
                    env=env,
                    publication_run_id=str(publication_run_id),
                    top_k=normalized_top_k,
                    effective_top_k=normalized_top_k,
                    query_text=query_text or "-",
                    parsed_categories=",".join(normalized_categories),
                    matched_count=matched_count,
                    returned_count=len(candidates),
                    order_by="typesense:_text_match/price_twd",
                    filters=filters_summary,
                    used_fts=use_fts,
                    used_trigram=False,
                    budget_aware_sorting=budget_aware_sorting,
                    retrieval_backend="typesense",
                    fallback_used=False,
                    latency_ms=latency_ms,
                )
            return P1RetrievalResult(items_by_category=result)
        except TypesenseError as exc:
            log_operation(
                "p1_retrieval_fallback",
                env=env,
                categories=",".join(normalized_categories),
                top_k=normalized_top_k,
                retrieval_backend="typesense",
                fallback_backend="postgresql",
                error_type=type(exc).__name__,
                reason=str(exc),
            )

    for category in normalized_categories:
        started = perf_counter()
        matched_count, candidates = fetch_category_candidates(
            db,
            category=category,
            top_k=normalized_top_k,
            demand=demand,
            use_trigram=use_trigram,
        )
        result[category] = candidates
        latency_ms = int((perf_counter() - started) * 1000)
        log_operation(
            "p1_retrieval",
            part_category=category,
            env=env,
            publication_run_id=str(publication_run_id),
            top_k=normalized_top_k,
            effective_top_k=normalized_top_k,
            query_text=query_text or "-",
            parsed_categories=",".join(normalized_categories),
            matched_count=matched_count,
            returned_count=len(candidates),
            order_by=order_by_summary,
            filters=filters_summary,
            used_fts=use_fts,
            used_trigram=use_trigram,
            budget_aware_sorting=budget_aware_sorting,
            retrieval_backend="postgresql",
            fallback_used=typesense_enabled,
            latency_ms=latency_ms,
        )

    return P1RetrievalResult(items_by_category=result)
