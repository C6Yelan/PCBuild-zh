# backend/services/crawler/staging/staging_events.py
"""Event helpers for crawler staging repo failure logging."""

from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy.orm import Session

from backend.core.obs_events import log_loki_event
from backend.models.crawler_staging import CrawlerIngestRun
from backend.services.crawler.staging.conventions import get_crawler_env

_RUN_SOURCE_CACHE: dict[str, str] = {}


def _resolve_run_source(db: Session, run_id: UUID) -> str:
    cache_key = str(run_id)
    if cache_key in _RUN_SOURCE_CACHE:
        return _RUN_SOURCE_CACHE[cache_key]
    try:
        run = db.get(CrawlerIngestRun, run_id)
        source = getattr(run, "source", None) or "unknown"
    except Exception:
        source = "unknown"
    _RUN_SOURCE_CACHE[cache_key] = source
    return source


def log_gate_result_failure_transition(
    *,
    logger: logging.Logger,
    db: Session,
    run_id: UUID,
    item_key: str,
    gate_name: str,
    status: str,
    detail_json: dict[str, object] | None,
) -> None:
    log_loki_event(
        logger,
        level=logging.ERROR,
        event="gate_result",
        source=_resolve_run_source(db, run_id),
        stage="staging",
        gate_name=gate_name,
        env=get_crawler_env(),
        run_id=str(run_id),
        item_key=item_key,
        status=status,
        detail_json=detail_json,
    )
