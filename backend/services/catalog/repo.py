# backend/services/catalog/repo.py
from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from backend.models.catalog import (
    CatalogSource,
    CatalogBrand,
    CatalogProduct,
    CatalogPriceSnapshot,
    CatalogSpecKey,
    CatalogProductSpec,
)


def upsert_source(db: Session, *, code: str, name: str | None = None) -> int:
    """
    upsert catalog_source by code, return source_id
    """
    name = name or code
    stmt = (
        pg_insert(CatalogSource)
        .values(code=code, name=name)
        .on_conflict_do_update(
            index_elements=[CatalogSource.code],
            set_={"name": sa.text("EXCLUDED.name")},
        )
        .returning(CatalogSource.id)
    )
    return int(db.execute(stmt).scalar_one())


def upsert_brand(db: Session, *, name: str) -> int:
    """
    upsert catalog_brand by name, return brand_id
    """
    stmt = (
        pg_insert(CatalogBrand)
        .values(name=name)
        .on_conflict_do_update(
            index_elements=[CatalogBrand.name],
            set_={"name": sa.text("EXCLUDED.name")},
        )
        .returning(CatalogBrand.id)
    )
    return int(db.execute(stmt).scalar_one())


def upsert_product(
    db: Session,
    *,
    source_id: int,
    source_item_key: str,
    category: str,
    title: str,
    url: str,
    sku_hint: str | None,
    run_id: UUID,
    brand_id: int | None = None,
) -> UUID:
    """
    upsert catalog_product by (source_id, source_item_key), return product_id
    - first_seen_run_id：只在 insert 時寫入（保留最早）
    - last_seen_run_id：每次 upsert 都更新
    """
    new_pid = uuid4()
    update_set: dict[str, object] = {
        "category": sa.text("EXCLUDED.category"),
        "title": sa.text("EXCLUDED.title"),
        "url": sa.text("EXCLUDED.url"),
        "sku_hint": sa.text("EXCLUDED.sku_hint"),
        "last_seen_run_id": sa.text("EXCLUDED.last_seen_run_id"),
        "updated_at": sa.func.now(),
    }
    if brand_id is not None:
        # Only backfill when current brand_id is NULL; never override non-NULL value.
        update_set["brand_id"] = sa.func.coalesce(CatalogProduct.brand_id, sa.text("EXCLUDED.brand_id"))

    stmt = (
        pg_insert(CatalogProduct)
        .values(
            product_id=new_pid,
            source_id=source_id,
            source_item_key=source_item_key,
            category=category,
            title=title,
            url=url,
            sku_hint=sku_hint,
            brand_id=brand_id,
            first_seen_run_id=run_id,
            last_seen_run_id=run_id,
            updated_at=sa.func.now(),
        )
        .on_conflict_do_update(
            constraint="uq_catalog_product_source_item_key",
            set_=update_set,
        )
        .returning(CatalogProduct.product_id)
    )
    return db.execute(stmt).scalar_one()


def upsert_price_snapshot(
    db: Session,
    *,
    product_id: UUID,
    run_id: UUID,
    price: int,
    currency: str,
) -> None:
    """
    upsert catalog_price_snapshot by (product_id, run_id)
    """
    stmt = (
        pg_insert(CatalogPriceSnapshot)
        .values(product_id=product_id, run_id=run_id, price=price, currency=currency)
        .on_conflict_do_update(
            constraint="uq_catalog_price_snapshot_product_run",
            set_={
                "price": sa.text("EXCLUDED.price"),
                "currency": sa.text("EXCLUDED.currency"),
                "captured_at": sa.func.now(),
            },
        )
    )
    db.execute(stmt)


def upsert_spec_key(db: Session, *, key: str) -> int:
    """
    upsert catalog_spec_key by key, return spec_key_id
    """
    stmt = (
        pg_insert(CatalogSpecKey)
        .values(key=key)
        .on_conflict_do_update(
            index_elements=[CatalogSpecKey.key],
            set_={"key": sa.text("EXCLUDED.key")},
        )
        .returning(CatalogSpecKey.id)
    )
    return int(db.execute(stmt).scalar_one())


def upsert_product_spec(
    db: Session,
    *,
    product_id: UUID,
    spec_key_id: int,
    value_text: str,
    unit: str | None,
) -> None:
    """
    upsert catalog_product_spec by (product_id, spec_key_id)
    """
    stmt = (
        pg_insert(CatalogProductSpec)
        .values(product_id=product_id, spec_key_id=spec_key_id, value_text=value_text, unit=unit)
        .on_conflict_do_update(
            constraint="uq_catalog_product_spec_product_key",
            set_={
                "value_text": sa.text("EXCLUDED.value_text"),
                "unit": sa.text("EXCLUDED.unit"),
            },
        )
    )
    db.execute(stmt)


def normalize_value_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (str, int, float, bool)):
        return str(v)
    # dict/list/others -> stable json
    try:
        return json.dumps(v, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(v)
