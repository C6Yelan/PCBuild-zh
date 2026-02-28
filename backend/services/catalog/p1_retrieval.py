# backend/services/catalog/p1_retrieval.py
from __future__ import annotations

from collections import defaultdict
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from backend.models.catalog import (
    CatalogPriceSnapshot,
    CatalogProduct,
    CatalogProductSpec,
    CatalogSource,
    CatalogSpecKey,
)
from backend.models.crawler_publication import (
    CrawlerPublicationPointer,
    CrawlerPublicationSetMember,
    CrawlerPublicationSetPointer,
)
from backend.services.chat.contracts import (
    P1Demand,
    P1RetrievalResult,
    PartCandidate,
    RetrievalLogItem,
)

DEFAULT_PUBLICATION_ENV = "prod"
DEFAULT_SPEC_KEY_ALLOWLIST: tuple[str, ...] = (
    "socket",
    "chipset",
    "form_factor",
    "ddr_gen",
    "capacity_gb",
    "speed_mhz",
    "watt",
    "pcie_gen",
    "length_mm",
)
DEFAULT_ORDER_BY_LABELS: tuple[str, ...] = (
    "price asc nulls last",
    "captured_at desc nulls last",
    "product_id asc",
)
CATEGORY_ALIASES: dict[str, str] = {
    "cpu": "CPU",
    "mb": "MB",
    "gpu": "GPU",
    "ram": "RAM",
}


def retrieve_topk_candidates(
    db: Session,
    *,
    categories: list[str],
    top_k: int,
    demand: P1Demand | None = None,
    env: str = DEFAULT_PUBLICATION_ENV,
) -> P1RetrievalResult:
    normalized_categories = _normalize_categories(categories)
    effective_top_k = max(1, min(int(top_k), 200))
    effective_demand = demand or P1Demand()

    publication_set = _get_active_publication_set(db, env=env)
    publication_id: UUID | None = publication_set[0] if publication_set is not None else None
    category_run_map: dict[str, UUID] = publication_set[1] if publication_set is not None else {}

    legacy_active_run_id = None if publication_set is not None else _get_legacy_active_run_id(db, env=env)
    latest_price_sq = None if (publication_set is not None or legacy_active_run_id is not None) else _build_latest_price_subquery()

    candidates_by_category: dict[str, list[PartCandidate]] = {}
    retrieval_log: list[RetrievalLogItem] = []

    for category in normalized_categories:
        filters: list[str] = [f"category={category}"]
        category_run_id: UUID | None = None

        if publication_set is not None:
            filters.append(f"publication_id={publication_id}")
            category_run_id = category_run_map.get(category)
            if category_run_id is None:
                filters.append("not_published=true")
                candidates_by_category[category] = []
                retrieval_log.append(
                    RetrievalLogItem(
                        category=category,
                        filters=filters,
                        order_by=list(DEFAULT_ORDER_BY_LABELS),
                        matched_count=0,
                        returned_count=0,
                        top_k=effective_top_k,
                        snapshot_id=None,
                    )
                )
                continue
            filters.append(f"snapshot_id={category_run_id}")
        elif legacy_active_run_id is not None:
            category_run_id = legacy_active_run_id
            filters.append(f"snapshot_id={category_run_id}")
        else:
            filters.append("snapshot_strategy=latest_price_per_product")

        if category_run_id is None:
            assert latest_price_sq is not None
            price_source = latest_price_sq
            price_join_on = latest_price_sq.c.product_id == CatalogProduct.product_id
            price_col = latest_price_sq.c.price
            currency_col = latest_price_sq.c.currency
            captured_at_col = latest_price_sq.c.captured_at
            price_run_col = latest_price_sq.c.run_id
        else:
            price_source = CatalogPriceSnapshot
            price_join_on = sa.and_(
                CatalogPriceSnapshot.product_id == CatalogProduct.product_id,
                CatalogPriceSnapshot.run_id == category_run_id,
            )
            price_col = CatalogPriceSnapshot.price
            currency_col = CatalogPriceSnapshot.currency
            captured_at_col = CatalogPriceSnapshot.captured_at
            price_run_col = CatalogPriceSnapshot.run_id

        filtered_stmt = (
            sa.select(
                CatalogProduct.product_id.label("part_id"),
                CatalogProduct.category.label("category"),
                CatalogProduct.title.label("display_name"),
                CatalogProduct.url.label("source_url"),
                CatalogSource.code.label("source"),
                price_col.label("price"),
                currency_col.label("currency"),
                captured_at_col.label("captured_at"),
                price_run_col.label("price_run_id"),
            )
            .select_from(CatalogProduct)
            .join(CatalogSource, CatalogSource.id == CatalogProduct.source_id)
            .join(price_source, price_join_on, isouter=True)
            .where(CatalogProduct.category == category)
        )

        if category_run_id is not None:
            filtered_stmt = filtered_stmt.where(CatalogProduct.last_seen_run_id == category_run_id)
            filters.append(f"last_seen_run_id={category_run_id}")

        if effective_demand.budget is not None:
            filtered_stmt = filtered_stmt.where(price_col <= effective_demand.budget)
            filters.append(f"budget<={effective_demand.budget}")

        if effective_demand.keyword:
            keyword = effective_demand.keyword
            filtered_stmt = filtered_stmt.where(CatalogProduct.title.ilike(f"%{keyword}%"))
            filters.append(f"title ilike %{keyword}%")

        matched_count = int(
            db.execute(
                sa.select(sa.func.count()).select_from(filtered_stmt.subquery())
            ).scalar_one()
        )

        rows = list(
            db.execute(
                filtered_stmt
                .order_by(
                    price_col.asc().nulls_last(),
                    captured_at_col.desc().nulls_last(),
                    CatalogProduct.product_id.asc(),
                )
                .limit(effective_top_k)
            ).mappings()
        )

        returned_product_ids = [row["part_id"] for row in rows]
        specs_by_product = _load_allowlisted_specs(
            db=db,
            product_ids=returned_product_ids,
            allowlist=DEFAULT_SPEC_KEY_ALLOWLIST,
        )

        category_candidates: list[PartCandidate] = []
        for row in rows:
            part_id = row["part_id"]
            category_candidates.append(
                PartCandidate(
                    part_id=part_id,
                    category=row["category"],
                    display_name=row["display_name"],
                    key_specs=specs_by_product.get(part_id, {}),
                    price=row["price"],
                    currency=row["currency"],
                    source=row["source"],
                    source_url=row["source_url"],
                    snapshot_id=category_run_id if category_run_id is not None else row["price_run_id"],
                    run_id=category_run_id if category_run_id is not None else row["price_run_id"],
                )
            )

        candidates_by_category[category] = category_candidates
        retrieval_log.append(
            RetrievalLogItem(
                category=category,
                filters=filters,
                order_by=list(DEFAULT_ORDER_BY_LABELS),
                matched_count=matched_count,
                returned_count=len(category_candidates),
                top_k=effective_top_k,
                snapshot_id=category_run_id,
            )
        )

    return P1RetrievalResult(
        publication_id=publication_id,
        snapshot_id=legacy_active_run_id,
        candidates=candidates_by_category,
        retrieval_log=retrieval_log,
    )


def _get_active_publication_set(db: Session, *, env: str) -> tuple[UUID, dict[str, UUID]] | None:
    pointer = db.get(CrawlerPublicationSetPointer, env)
    if pointer is None:
        return None

    rows = db.execute(
        sa.select(
            CrawlerPublicationSetMember.category,
            CrawlerPublicationSetMember.run_id,
        )
        .where(CrawlerPublicationSetMember.publication_id == pointer.publication_id)
        .order_by(CrawlerPublicationSetMember.id.asc())
    ).all()

    category_to_run: dict[str, UUID] = {}
    for category, run_id in rows:
        canonical_category = _canonicalize_category(str(category))
        category_to_run[canonical_category] = run_id

    return pointer.publication_id, category_to_run


def _get_legacy_active_run_id(db: Session, *, env: str) -> UUID | None:
    pointer = db.get(CrawlerPublicationPointer, env)
    return pointer.run_id if pointer is not None else None


def _build_latest_price_subquery() -> sa.Subquery:
    ranked_price_sq = (
        sa.select(
            CatalogPriceSnapshot.product_id.label("product_id"),
            CatalogPriceSnapshot.run_id.label("run_id"),
            CatalogPriceSnapshot.price.label("price"),
            CatalogPriceSnapshot.currency.label("currency"),
            CatalogPriceSnapshot.captured_at.label("captured_at"),
            sa.func.row_number().over(
                partition_by=CatalogPriceSnapshot.product_id,
                order_by=(
                    CatalogPriceSnapshot.captured_at.desc(),
                    CatalogPriceSnapshot.id.desc(),
                ),
            ).label("rn"),
        )
        .select_from(CatalogPriceSnapshot)
        .subquery()
    )

    return (
        sa.select(
            ranked_price_sq.c.product_id,
            ranked_price_sq.c.run_id,
            ranked_price_sq.c.price,
            ranked_price_sq.c.currency,
            ranked_price_sq.c.captured_at,
        )
        .where(ranked_price_sq.c.rn == 1)
        .subquery()
    )


def _load_allowlisted_specs(
    db: Session,
    *,
    product_ids: list[UUID],
    allowlist: tuple[str, ...],
) -> dict[UUID, dict[str, str]]:
    if not product_ids:
        return {}

    rows = db.execute(
        sa.select(
            CatalogProductSpec.product_id.label("product_id"),
            CatalogSpecKey.key.label("spec_key"),
            CatalogProductSpec.value_text.label("value_text"),
            CatalogProductSpec.unit.label("unit"),
        )
        .select_from(CatalogProductSpec)
        .join(CatalogSpecKey, CatalogSpecKey.id == CatalogProductSpec.spec_key_id)
        .where(CatalogProductSpec.product_id.in_(product_ids))
        .where(CatalogSpecKey.key.in_(allowlist))
        .order_by(CatalogProductSpec.product_id.asc(), CatalogSpecKey.key.asc())
    ).mappings()

    specs: dict[UUID, dict[str, str]] = defaultdict(dict)
    for row in rows:
        product_id: UUID = row["product_id"]
        key = str(row["spec_key"])
        value_text = str(row["value_text"])
        unit_raw = row["unit"]
        unit = (str(unit_raw).strip() if unit_raw is not None else "")
        specs[product_id][key] = f"{value_text}{unit}" if unit else value_text

    return dict(specs)


def _normalize_categories(categories: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in categories:
        canonical = _canonicalize_category(raw)
        if not canonical:
            continue
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(canonical)
    return out


def _canonicalize_category(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    lowered = value.lower()
    canonical = CATEGORY_ALIASES.get(lowered, value.upper())
    return canonical
