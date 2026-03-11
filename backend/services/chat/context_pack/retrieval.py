"""Chat retrieval implementation.

``retrieve_topk_candidates`` is the callable boundary used by chat orchestration.
``build_category_retrieval_stmt`` is a stable SQL seam for ordering-contract
tests and future refactors without reaching into private helpers.
"""

# backend/services/chat/context_pack/retrieval.py
from __future__ import annotations

from time import perf_counter
from typing import Any

import sqlalchemy as sa
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session

from backend.core.oplog import log_operation
from backend.models.catalog import (
    CatalogPriceSnapshot,
    CatalogProduct,
    CatalogProductSpec,
    CatalogSource,
    CatalogSpecKey,
)
from backend.models.crawler_publication import CrawlerPublicationPointer

P1_ORDER_BY = "price ASC NULLS LAST, part_id ASC" # 價格由低到高，價格相同則 part_id 由小到大


class P1Demand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_price: int | None = Field(default=None, ge=0) # ge = greater than or equal to 0
    max_price: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _validate_price_range(self) -> "P1Demand":
        if self.min_price is not None and self.max_price is not None and self.min_price > self.max_price:
            raise ValueError("min_price must be <= max_price")
        return self


class CandidatePart(BaseModel):
    model_config = ConfigDict(extra="forbid")

    part_id: str
    category: str
    display_name: str
    key_specs: dict[str, Any]
    price: int | None = None
    source: str
    source_url: str
    snapshot_id: str | None = None
    run_id: str | None = None

    @model_validator(mode="after")
    def _validate_lineage(self) -> "CandidatePart":
        if self.snapshot_id or self.run_id:
            return self
        raise ValueError("CandidatePart requires snapshot_id or run_id")


class P1RetrievalResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items_by_category: dict[str, list[CandidatePart]]


def _normalize_categories(categories: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for raw in categories:
        value = str(raw).strip()
        if not value or value in seen:
            continue
        deduped.append(value)
        seen.add(value)
    return deduped


def _normalize_top_k(top_k: int) -> int:
    return max(1, min(int(top_k), 200))


def _summarize_filters(demand: P1Demand | None) -> str:
    if demand is None:
        return "none"
    parts: list[str] = []
    if demand.min_price is not None:
        parts.append(f"min_price>={demand.min_price}")
    if demand.max_price is not None:
        parts.append(f"max_price<={demand.max_price}")
    return ",".join(parts) if parts else "none"


def _build_specs_subquery() -> sa.Subquery:
    return (
        sa.select(
            CatalogProductSpec.product_id.label("product_id"),
            sa.func.jsonb_object_agg(CatalogSpecKey.key, CatalogProductSpec.value_text).label("key_specs"),
        )
        .select_from(CatalogProductSpec)
        .join(CatalogSpecKey, CatalogSpecKey.id == CatalogProductSpec.spec_key_id)
        .group_by(CatalogProductSpec.product_id)
        .subquery()
    )


def _apply_demand_filters(
    stmt: sa.Select[Any],
    *,
    demand: P1Demand | None,
) -> sa.Select[Any]:
    if demand is None:
        return stmt
    if demand.min_price is not None:
        stmt = stmt.where(CatalogPriceSnapshot.price >= demand.min_price)
    if demand.max_price is not None:
        stmt = stmt.where(CatalogPriceSnapshot.price <= demand.max_price)
    return stmt


def _build_count_stmt(
    *,
    category: str,
    demand: P1Demand | None,
) -> sa.Select[Any]:
    stmt = (
        sa.select(sa.func.count())
        .select_from(CatalogProduct)
        .join(
            CatalogPriceSnapshot,
            sa.and_(
                CatalogPriceSnapshot.product_id == CatalogProduct.product_id,
                CatalogPriceSnapshot.run_id == CatalogProduct.last_seen_run_id,
            ),
            isouter=True,
        )
        .where(
            CatalogProduct.category == category,
            CatalogProduct.last_seen_run_id.is_not(None),
        )
    )
    return _apply_demand_filters(stmt, demand=demand)


def build_category_retrieval_stmt(
    *,
    category: str,
    top_k: int,
    demand: P1Demand | None,
) -> sa.Select[Any]:
    specs_sq = _build_specs_subquery()
    stmt = (
        sa.select(
            CatalogProduct.product_id.label("part_id"),
            CatalogProduct.category,
            CatalogProduct.title.label("display_name"),
            specs_sq.c.key_specs.label("key_specs"),
            CatalogPriceSnapshot.price.label("price"),
            CatalogSource.code.label("source"),
            CatalogProduct.url.label("source_url"),
            CatalogProduct.last_seen_run_id.label("item_run_id"),
        )
        .select_from(CatalogProduct)
        .join(CatalogSource, CatalogSource.id == CatalogProduct.source_id)
        .join(
            CatalogPriceSnapshot,
            sa.and_(
                CatalogPriceSnapshot.product_id == CatalogProduct.product_id,
                CatalogPriceSnapshot.run_id == CatalogProduct.last_seen_run_id,
            ),
            isouter=True,
        )
        .join(specs_sq, specs_sq.c.product_id == CatalogProduct.product_id, isouter=True)
        .where(
            CatalogProduct.category == category,
            CatalogProduct.last_seen_run_id.is_not(None),
        )
        .order_by(
            CatalogPriceSnapshot.price.asc().nullslast(),
            CatalogProduct.product_id.asc(),
        )
        .limit(top_k)
    )
    return _apply_demand_filters(stmt, demand=demand)


def retrieve_topk_candidates(
    db: Session,
    *,
    categories: list[str],
    top_k: int,
    demand: P1Demand | None = None,
    env: str = "prod",
) -> P1RetrievalResult:
    normalized_categories = _normalize_categories(categories)
    normalized_top_k = _normalize_top_k(top_k)
    if not normalized_categories:
        return P1RetrievalResult(items_by_category={})

    ptr = db.get(CrawlerPublicationPointer, env)
    if ptr is None:
        raise RuntimeError(f"crawler_publication_pointer not found for env={env!r}; please publish first")

    publication_run_id = ptr.run_id
    filters_summary = _summarize_filters(demand)
    result: dict[str, list[CandidatePart]] = {}

    for category in normalized_categories:
        started = perf_counter()
        matched_count = int(db.execute(_build_count_stmt(category=category, demand=demand)).scalar_one())

        rows = list(
            db.execute(
                build_category_retrieval_stmt(
                    category=category,
                    top_k=normalized_top_k,
                    demand=demand,
                )
            ).mappings()
        )

        candidates = [
            CandidatePart(
                part_id=str(row["part_id"]),
                category=str(row["category"]),
                display_name=str(row["display_name"]),
                key_specs=row["key_specs"] if isinstance(row["key_specs"], dict) else {},
                price=row["price"],
                source=str(row["source"]),
                source_url=str(row["source_url"]),
                run_id=str(row["item_run_id"]),
            )
            for row in rows[:normalized_top_k]
        ]

        result[category] = candidates

        latency_ms = int((perf_counter() - started) * 1000)
        log_operation(
            "p1_retrieval",
            part_category=category,
            env=env,
            publication_run_id=str(publication_run_id),
            top_k=normalized_top_k,
            matched_count=matched_count,
            returned_count=len(candidates),
            order_by=P1_ORDER_BY,
            filters=filters_summary,
            latency_ms=latency_ms,
        )

    return P1RetrievalResult(items_by_category=result)
