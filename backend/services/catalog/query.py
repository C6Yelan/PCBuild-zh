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
from backend.models.crawler_publication import CrawlerPublicationPointer


def list_products_with_latest_price(
    db: Session,
    *,
    category: str | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
    include_specs: bool = False,
    env: str = "prod",
) -> list[dict[str, Any]]:
    """
    讀取 catalog_product，並以「已發佈版本」為唯一讀取口徑：
    - 先取得 crawler_publication_pointer(env) 指向的 run_id（current release）
    - 僅回傳 last_seen_run_id == current run_id 的商品
    - 價格以 catalog_price_snapshot (product_id, run_id) 直接 join（每個 run 對每個 product 只會有一筆）
    """
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))

    ptr = db.get(CrawlerPublicationPointer, env)
    if ptr is None:
        raise RuntimeError(f"crawler_publication_pointer not found for env={env!r}; please publish first")

    current_run_id = ptr.run_id

    stmt = (
        sa.select(
            CatalogProduct.product_id,
            CatalogProduct.category,
            CatalogProduct.title,
            CatalogProduct.url,
            CatalogProduct.sku_hint,
            CatalogProduct.updated_at,
            CatalogPriceSnapshot.price.label("price"),
            CatalogPriceSnapshot.currency.label("currency"),
            CatalogPriceSnapshot.captured_at.label("captured_at"),
        )
        .select_from(CatalogProduct)
        .join(
            CatalogPriceSnapshot,
            sa.and_(
                CatalogPriceSnapshot.product_id == CatalogProduct.product_id,
                CatalogPriceSnapshot.run_id == current_run_id,
            ),
            isouter=True,
        )
        .where(CatalogProduct.last_seen_run_id == current_run_id)
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

    specs_map = dict(db.execute(sa.select(specs_sq.c.product_id, specs_sq.c.specs)).all())

    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["specs"] = specs_map.get(r["product_id"]) or {}
        out.append(d)
    return out
