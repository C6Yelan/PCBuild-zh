# backend/services/chat/context_pack/retrieval_sql.py
from __future__ import annotations

from typing import Any

import sqlalchemy as sa

from backend.models.catalog import (
    CatalogBrand,
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
P1_ORDER_BY_SEARCH = (
    "search_match ASC, fts_rank DESC, trigram_similarity DESC, "
    "budget_distance ASC, part_id ASC"
)


def build_specs_subquery() -> sa.Subquery:
    return (
        sa.select(
            CatalogProductSpec.product_id.label("product_id"),
            sa.func.jsonb_object_agg(CatalogSpecKey.key, CatalogProductSpec.value_text).label("key_specs"),
            sa.func.string_agg(
                sa.func.concat_ws(" ", CatalogSpecKey.key, CatalogProductSpec.value_text),
                " ",
            ).label("search_text"),
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
    search_rank: sa.ColumnElement[Any] | None = None,
    trigram_similarity: sa.ColumnElement[Any] | None = None,
    search_match_rank: sa.ColumnElement[Any] | None = None,
) -> tuple[sa.ColumnElement[Any], ...]:
    if search_rank is not None and trigram_similarity is not None and search_match_rank is not None:
        return (
            search_match_rank.asc(),
            search_rank.desc(),
            trigram_similarity.desc(),
            *build_budget_order_by_clauses(demand=demand),
        )

    return build_budget_order_by_clauses(demand=demand)


def build_budget_order_by_clauses(
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


def has_search_query(demand: P1Demand | None) -> bool:
    return demand is not None and bool(demand.query_text)


def build_search_document(specs_sq: sa.Subquery) -> sa.ColumnElement[str]:
    return sa.func.concat_ws(
        " ",
        sa.func.coalesce(CatalogBrand.name, ""),
        sa.func.coalesce(CatalogProduct.title, ""),
        sa.func.coalesce(CatalogProduct.sku_hint, ""),
        sa.func.coalesce(specs_sq.c.search_text, ""),
    )


def _fts_config() -> sa.ColumnElement[str]:
    return sa.literal_column("'simple'")


def build_search_query(demand: P1Demand | None) -> sa.ColumnElement[Any] | None:
    if not has_search_query(demand):
        return None
    assert demand is not None
    return sa.func.websearch_to_tsquery(_fts_config(), demand.query_text)


def describe_order_by(
    demand: P1Demand | None,
    *,
    use_trigram: bool = False,
) -> str:
    if has_search_query(demand):
        parts = ["search_match", "fts_rank DESC"]
        if use_trigram:
            parts.append("trigram_similarity DESC")
        if demand is not None and (
            demand.min_price is not None
            or demand.max_price is not None
            or demand.target_price is not None
            or demand.budget is not None
        ):
            parts.append("budget_distance ASC")
        parts.append("part_id ASC")
        return ", ".join(parts)
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
    use_trigram: bool = False,
) -> sa.Select[Any]:
    specs_sq = build_specs_subquery()
    search_document = build_search_document(specs_sq)
    search_vector = sa.func.to_tsvector(_fts_config(), search_document)
    ts_query = build_search_query(demand)
    search_rank = sa.literal(0.0)
    trigram_similarity = sa.literal(0.0)
    search_match_rank = sa.literal(0)
    if ts_query is not None:
        search_rank = sa.func.ts_rank_cd(search_vector, ts_query)
        fts_matches = search_vector.op("@@")(ts_query)
        trigram_match_score = sa.literal(0.0)
        trigram_match = sa.false()
        if use_trigram:
            trigram_match_score = sa.func.greatest(
                sa.func.similarity(sa.func.coalesce(CatalogProduct.title, ""), demand.query_text),
                sa.func.similarity(sa.func.coalesce(CatalogProduct.sku_hint, ""), demand.query_text),
                sa.func.similarity(search_document, demand.query_text),
            )
            trigram_similarity = trigram_match_score
            trigram_match = trigram_match_score >= 0.12
        search_match_rank = sa.case(
            (fts_matches, 0),
            (trigram_match, 1),
            else_=2,
        )
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
        .join(CatalogBrand, CatalogBrand.id == CatalogProduct.brand_id, isouter=True)
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
    return stmt.order_by(
        *build_order_by_clauses(
            demand=demand,
            search_rank=search_rank if ts_query is not None else None,
            trigram_similarity=trigram_similarity if ts_query is not None else None,
            search_match_rank=search_match_rank if ts_query is not None else None,
        )
    ).limit(top_k)
