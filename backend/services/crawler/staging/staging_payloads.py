# backend/services/crawler/staging/staging_payloads.py
"""Payload builders for crawler staging item and gate upserts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.services.crawler.staging.conventions import make_item_key


@dataclass(frozen=True)
class StagingItemPayload:
    item_key: str
    category: str
    title: str
    url: str
    price: int
    currency: str
    sku_hint: str | None
    canonical_json: dict[str, Any]


@dataclass(frozen=True)
class StagingGatePayload:
    gate_name: str
    status: str
    detail_json: dict[str, Any] | None


def _validate_item(item: dict[str, Any]) -> None:
    required = ("category", "title", "url", "price", "currency")
    missing = [key for key in required if item.get(key) in (None, "")]
    if missing:
        raise ValueError(f"staging item 缺必要欄位: {missing}")

    price = item.get("price")
    try:
        price_i = int(price)
    except Exception as exc:
        raise ValueError(f"price 無法轉成 int: {price!r}") from exc
    if price_i < 0:
        raise ValueError(f"price 不可為負數: {price_i}")


def build_staging_item_payload(
    *,
    source: str,
    item: dict[str, Any],
) -> StagingItemPayload:
    _validate_item(item)
    return StagingItemPayload(
        item_key=make_item_key(source, item),
        category=str(item["category"]),
        title=str(item["title"]),
        url=str(item["url"]),
        price=int(item["price"]),
        currency=str(item["currency"]),
        sku_hint=(str(item["sku_hint"]) if item.get("sku_hint") is not None else None),
        canonical_json=item,
    )


def build_staging_gate_payload(
    *,
    gate_name: str,
    status: str,
    detail_json: dict[str, Any] | None = None,
) -> StagingGatePayload:
    if status not in ("pass", "fail"):
        raise ValueError("status 只能是 'pass' 或 'fail'")
    return StagingGatePayload(
        gate_name=gate_name,
        status=status,
        detail_json=detail_json,
    )
