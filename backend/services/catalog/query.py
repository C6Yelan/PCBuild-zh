# backend/services/catalog/query.py
from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from backend.models.catalog import (
    CatalogProduct,
    CatalogPriceSnapshot,
    CatalogProductSpec,
    CatalogSpecKey,
)


def list_products_with_latest_price(
    db: Session,
    *,
    category: str | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
    include_specs: bool = False,
) -> list[dict[str, Any]]:
    """
    讀取 catalog_product，並用 LATERAL 取每個 product 的最新價格（price_snapshot.captured_at 最大者）。
    可選擇 include_specs 以聚合成 specs dict（key -> value_text）。
    """
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))

    # LATERAL：對每個 CatalogProduct 做一次「最新價格」子查詢
    lp = (
        sa.select(
            CatalogPriceSnapshot.price.label("price"),
            CatalogPriceSnapshot.currency.label("currency"),
            CatalogPriceSnapshot.captured_at.label("captured_at"),
        )
        .where(CatalogPriceSnapshot.product_id == CatalogProduct.product_id)
        .order_by(CatalogPriceSnapshot.captured_at.desc())
        .limit(1)
        .lateral("lp")
    )

    stmt = (
        sa.select(
            CatalogProduct.product_id,
            CatalogProduct.category,
            CatalogProduct.title,
            CatalogProduct.url,
            CatalogProduct.sku_hint,
            CatalogProduct.updated_at,
            lp.c.price,
            lp.c.currency,
            lp.c.captured_at,
        )
        .select_from(CatalogProduct)
        .join(lp, sa.true(), isouter=True)
        .order_by(CatalogProduct.updated_at.desc(), CatalogProduct.product_id)
        .limit(limit)
        .offset(offset)
    )

    if category:
        stmt = stmt.where(CatalogProduct.category == category)

    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            sa.or_(
                CatalogProduct.title.ilike(like),
                CatalogProduct.sku_hint.ilike(like),
            )
        )

    rows = list(db.execute(stmt).mappings())

    if not include_specs or not rows:
        return [dict(r) for r in rows]

    # 聚合 specs：每個 product_id -> jsonb_object_agg(spec_key.key, value_text)
    pids = [r["product_id"] for r in rows]

    specs_sq = (
        sa.select(
            CatalogProductSpec.product_id.label("product_id"),
            sa.func.jsonb_object_agg(CatalogSpecKey.key, CatalogProductSpec.value_text).label("specs"),
        )
        .select_from(CatalogProductSpec)
        .join(CatalogSpecKey, CatalogSpecKey.id == CatalogProductSpec.spec_key_id)
        .where(CatalogProductSpec.product_id.in_(pids))
        .group_by(CatalogProductSpec.product_id)
        .subquery()
    )

    specs_map = dict(
        db.execute(sa.select(specs_sq.c.product_id, specs_sq.c.specs)).all()
    )

    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["specs"] = specs_map.get(r["product_id"]) or {}
        out.append(d)
    return out
