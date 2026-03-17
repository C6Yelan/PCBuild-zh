# backend/tools/ops/crawler/incremental/incremental_fetch_state.py
"""State and persistence helpers for incremental fetch phases."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from backend.services.crawler.fetch_state_repo import upsert_fetch_state


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def calculate_content_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def header_value(headers: Any, name: str) -> str | None:
    target = name.lower()
    for key, value in dict(headers).items():
        if str(key).lower() == target:
            return str(value)
    return None


def build_fetch_headers(state: Any) -> dict[str, str]:
    headers: dict[str, str] = {}
    if state is None:
        return headers
    if state.etag:
        headers["If-None-Match"] = str(state.etag)
    if state.last_modified:
        headers["If-Modified-Since"] = str(state.last_modified)
    return headers


def record_fetch_state(
    db: Session,
    *,
    dry_run: bool,
    source: str,
    part_type: str,
    url: str,
    etag: str | None,
    last_modified: str | None,
    content_sha256: str | None,
    last_status_code: int | None,
    last_success_at: datetime | None = None,
) -> None:
    if dry_run:
        return
    upsert_fetch_state(
        db,
        source=source,
        part_type=part_type,
        url=url,
        etag=etag,
        last_modified=last_modified,
        content_sha256=content_sha256,
        last_status_code=last_status_code,
        last_success_at=last_success_at,
        updated_at=utc_now(),
    )
    db.commit()
