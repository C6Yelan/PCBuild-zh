# backend/tools/ops/incremental_fetch.py
"""Fetch and conditional-state helpers for incremental crawler runs."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.orm import Session

from backend.services.crawler.fetch_state_repo import get_fetch_state, upsert_fetch_state
from backend.tools.crawler.io.artifact_io import write_json_file


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _header_value(headers: Any, name: str) -> str | None:
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


def collect_changed_parts(
    *,
    db: Session,
    client: Any,
    source: str,
    run_id: str,
    run_dir: Path,
    targets: list[tuple[str, str]],
    dry_run: bool,
    summary: dict[str, Any],
    log_event: Callable[..., None],
) -> tuple[list[dict[str, Any]], int]:
    changed_parts: list[dict[str, Any]] = []
    rc = 0

    for part_type, url in targets:
        part_dir = run_dir / "parts" / part_type
        snapshot_dir = part_dir / "snapshot"

        part_entry: dict[str, Any] = {
            "part_type": part_type,
            "url": url,
            "status": "pending",
            "no_change": False,
            "skip_reason": None,
            "snapshot_dir": None,
            "fetch": {},
            "parse": None,
            "stage": None,
        }
        summary["parts"].append(part_entry)

        state = get_fetch_state(db, source=source, part_type=part_type, url=url)
        req_headers = build_fetch_headers(state)
        fetch_started = utc_now()
        fetch_used_conditional = bool(req_headers)

        try:
            result = client.fetch(url, headers=req_headers or None)
        except Exception as exc:
            part_entry["status"] = "fetch_error"
            part_entry["fetch"] = {
                "started_at": fetch_started.isoformat(),
                "error": str(exc),
                "exc_type": type(exc).__name__,
                "used_conditional_headers": fetch_used_conditional,
            }
            summary["counts"]["parts_failed"] += 1
            summary["errors"].append(f"fetch_failed[{part_type}]: {exc}")
            log_event(
                event="t10_fetch",
                source=source,
                stage="fetch",
                run_id=run_id,
                part_type=part_type,
                url=url,
                status="error",
                used_conditional_headers=fetch_used_conditional,
                error=str(exc),
                exc_type=type(exc).__name__,
            )
            rc = 2
            continue

        baseline_success = bool(state is not None and state.last_success_at is not None)
        no_change_reason: str | None = None

        if result.status_code == 304 and not baseline_success:
            result = client.fetch(url, headers=None)
            fetch_used_conditional = False

        content_sha256 = _sha256_text(result.text) if result.status_code == 200 else None
        if result.status_code == 304:
            no_change_reason = "http_304"
        elif (
            result.status_code == 200
            and baseline_success
            and state is not None
            and state.content_sha256
            and content_sha256
            and str(state.content_sha256) == str(content_sha256)
        ):
            no_change_reason = "content_sha256_same"

        etag = _header_value(result.headers, "etag")
        last_modified = _header_value(result.headers, "last-modified")
        now = utc_now()

        part_entry["fetch"] = {
            "started_at": fetch_started.isoformat(),
            "fetched_at": now.isoformat(),
            "status_code": int(result.status_code),
            "final_url": str(result.final_url),
            "etag": etag,
            "last_modified": last_modified,
            "content_sha256": content_sha256,
            "used_conditional_headers": fetch_used_conditional,
            "request_headers": dict(req_headers),
        }

        log_event(
            event="t10_fetch",
            source=source,
            stage="fetch",
            run_id=run_id,
            part_type=part_type,
            url=url,
            final_url=str(result.final_url),
            status_code=int(result.status_code),
            used_conditional_headers=fetch_used_conditional,
        )

        if result.status_code not in (200, 304):
            part_entry["status"] = "fetch_error"
            summary["counts"]["parts_failed"] += 1
            summary["errors"].append(
                f"unexpected_status[{part_type}]: status_code={result.status_code}"
            )
            record_fetch_state(
                db,
                dry_run=dry_run,
                source=source,
                part_type=part_type,
                url=url,
                etag=etag,
                last_modified=last_modified,
                content_sha256=content_sha256,
                last_status_code=int(result.status_code),
            )
            rc = 2
            continue

        if result.status_code == 200:
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            part_entry["snapshot_dir"] = str(snapshot_dir)
            (snapshot_dir / "body.txt").write_text(result.text, encoding="utf-8", errors="replace")
            write_json_file(
                snapshot_dir / "meta.json",
                {
                    "retrieved_at_utc": now.strftime("%Y%m%dT%H%M%SZ"),
                    "url": url,
                    "final_url": str(result.final_url),
                    "status_code": int(result.status_code),
                    "content_sha256": content_sha256,
                    "headers": dict(result.headers),
                },
            )

        record_fetch_state(
            db,
            dry_run=dry_run,
            source=source,
            part_type=part_type,
            url=url,
            etag=etag,
            last_modified=last_modified,
            content_sha256=content_sha256,
            last_status_code=int(result.status_code),
        )

        if no_change_reason:
            part_entry["status"] = "no_change"
            part_entry["no_change"] = True
            part_entry["skip_reason"] = no_change_reason
            summary["counts"]["parts_no_change"] += 1
            log_event(
                event="t10_no_change",
                source=source,
                stage="fetch",
                run_id=run_id,
                part_type=part_type,
                reason=no_change_reason,
                status_code=int(result.status_code),
            )
            record_fetch_state(
                db,
                dry_run=dry_run,
                source=source,
                part_type=part_type,
                url=url,
                etag=etag,
                last_modified=last_modified,
                content_sha256=content_sha256,
                last_status_code=int(result.status_code),
                last_success_at=now,
            )
            continue

        part_entry["status"] = "changed"
        summary["counts"]["parts_changed"] += 1
        changed_parts.append(
            {
                "part_type": part_type,
                "url": url,
                "snapshot_dir": str(snapshot_dir),
                "entry_ref": part_entry,
            }
        )

    return changed_parts, rc
