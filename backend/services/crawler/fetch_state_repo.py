# backend/services/crawler/fetch_state_repo.py
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.models.crawler_fetch_state import CrawlerFetchState


def get_fetch_state(db: Session, *, source: str, part_type: str, url: str) -> CrawlerFetchState | None:
    return db.get(CrawlerFetchState, (source, part_type, url))


def upsert_fetch_state(
    db: Session,
    *,
    source: str,
    part_type: str,
    url: str,
    etag: str | None = None,
    last_modified: str | None = None,
    content_sha256: str | None = None,
    last_status_code: int | None = None,
    last_success_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> CrawlerFetchState:
    row = db.get(CrawlerFetchState, (source, part_type, url))
    now = updated_at or datetime.now(timezone.utc)

    if row is None:
        row = CrawlerFetchState(
            source=source,
            part_type=part_type,
            url=url,
            etag=etag,
            last_modified=last_modified,
            content_sha256=content_sha256,
            last_status_code=last_status_code,
            last_success_at=last_success_at,
            updated_at=now,
        )
        db.add(row)
        db.flush()
        return row

    if etag is not None:
        row.etag = etag
    if last_modified is not None:
        row.last_modified = last_modified
    if content_sha256 is not None:
        row.content_sha256 = content_sha256
    if last_status_code is not None:
        row.last_status_code = last_status_code
    if last_success_at is not None:
        row.last_success_at = last_success_at
    row.updated_at = now
    db.flush()
    return row
