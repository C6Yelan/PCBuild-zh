# backend/services/crawler/staging/staging_rows.py
"""ORM row helpers for crawler staging persistence."""

from __future__ import annotations

from uuid import UUID

from backend.models.crawler_staging import CrawlerStgGateResult, CrawlerStgItem
from backend.services.crawler.staging.staging_payloads import (
    StagingGatePayload,
    StagingItemPayload,
)


def create_staging_item_row(
    *,
    run_id: UUID,
    payload: StagingItemPayload,
) -> CrawlerStgItem:
    return CrawlerStgItem(
        run_id=run_id,
        item_key=payload.item_key,
        category=payload.category,
        title=payload.title,
        url=payload.url,
        price=payload.price,
        currency=payload.currency,
        sku_hint=payload.sku_hint,
        canonical_json=payload.canonical_json,
    )


def apply_staging_item_payload(
    row: CrawlerStgItem,
    *,
    payload: StagingItemPayload,
) -> None:
    row.category = payload.category
    row.title = payload.title
    row.url = payload.url
    row.price = payload.price
    row.currency = payload.currency
    row.sku_hint = payload.sku_hint
    row.canonical_json = payload.canonical_json


def create_staging_gate_result_row(
    *,
    run_id: UUID,
    item_key: str,
    payload: StagingGatePayload,
) -> CrawlerStgGateResult:
    return CrawlerStgGateResult(
        run_id=run_id,
        item_key=item_key,
        gate_name=payload.gate_name,
        status=payload.status,
        detail_json=payload.detail_json,
    )


def apply_staging_gate_payload(
    row: CrawlerStgGateResult,
    *,
    payload: StagingGatePayload,
) -> None:
    row.status = payload.status
    row.detail_json = payload.detail_json
