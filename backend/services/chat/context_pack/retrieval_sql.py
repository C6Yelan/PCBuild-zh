# backend/services/chat/context_pack/retrieval_sql.py
from __future__ import annotations

from typing import Any

import sqlalchemy as sa

from backend.models.catalog import (
    CatalogPriceSnapshot,
    CatalogProduct,
    CatalogProductSpec,
    CatalogSource,
    CatalogSpecKey,
)

from .retrieval_contracts import P1Demand

P1_ORDER_BY = "price ASC NULLS LAST, part_id ASC"
P1_ORDER_BY_BUDGET_AWARE = (
    "in_price_range ASC, budget_distance ASC, price ASC NULLS LAST, part_id ASC"
)


def build_specs_subquery() -> sa.Subquery:
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


def apply_demand_filters(
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


def _budget_target_price(demand: P1Demand | None) -> int | None:
    if demand is None:
        return None
    if demand.target_price is not None:
        return demand.target_price
    if demand.min_price is not None and demand.max_price is not None:
        return (demand.min_price + demand.max_price) // 2
    if demand.max_price is not None:
        return demand.max_price
    if demand.min_price is not None:
        return demand.min_price
    return None


def build_order_by_clauses(
    *,
    demand: P1Demand | None,
) -> tuple[sa.ColumnElement[Any], ...]:
    if demand is None or (
        demand.min_price is None
        and demand.max_price is None
        and demand.target_price is None
        and demand.budget is None
    ):
        return (
            CatalogPriceSnapshot.price.asc().nullslast(),
            CatalogProduct.product_id.asc(),
        )

    in_range_predicate = CatalogPriceSnapshot.price.is_not(None)
    if demand.min_price is not None:
        in_range_predicate = sa.and_(in_range_predicate, CatalogPriceSnapshot.price >= demand.min_price)
    if demand.max_price is not None:
        in_range_predicate = sa.and_(in_range_predicate, CatalogPriceSnapshot.price <= demand.max_price)

    target_price = _budget_target_price(demand)
    if target_price is None:
        target_price = 0

    budget_distance = sa.case(
        (
            CatalogPriceSnapshot.price.is_not(None),
            sa.func.abs(CatalogPriceSnapshot.price - sa.literal(target_price)),
        ),
        else_=sa.literal(2147483647),
    )
    in_range_rank = sa.case(
        (in_range_predicate, 0),
        (CatalogPriceSnapshot.price.is_not(None), 1),
        else_=2,
    )
    return (
        in_range_rank.asc(),
        budget_distance.asc(),
        CatalogPriceSnapshot.price.asc().nullslast(),
        CatalogProduct.product_id.asc(),
    )


def describe_order_by(demand: P1Demand | None) -> str:
    if demand is None or (
        demand.min_price is None
        and demand.max_price is None
        and demand.target_price is None
        and demand.budget is None
    ):
        return P1_ORDER_BY
    return P1_ORDER_BY_BUDGET_AWARE


def build_retrieval_count_stmt(
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
    return apply_demand_filters(stmt, demand=demand)


def build_category_retrieval_stmt(
    *,
    category: str,
    top_k: int,
    demand: P1Demand | None,
) -> sa.Select[Any]:
    specs_sq = build_specs_subquery()
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
    )
    stmt = apply_demand_filters(stmt, demand=demand)
    return stmt.order_by(*build_order_by_clauses(demand=demand)).limit(top_k)
