# backend/tools/ops/crawler/incremental/incremental_fetch_runtime.py
"""Runtime helpers for incremental fetch/no-change orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from sqlalchemy.orm import Session

from backend.services.crawler.fetch_state_repo import get_fetch_state

from .incremental_fetch_support import (
    apply_no_change_outcome,
    apply_unexpected_fetch_status,
    build_fetch_part_entry,
    build_fetch_payload,
    compute_no_change_reason,
    record_fetch_exception,
    write_fetch_snapshot_artifacts,
)
from .incremental_fetch_state import (
    build_fetch_headers,
    calculate_content_sha256,
    header_value,
    record_fetch_state,
    utc_now,
)


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

        part_entry = build_fetch_part_entry(part_type, url)
        summary["parts"].append(part_entry)

        state = get_fetch_state(db, source=source, part_type=part_type, url=url)
        req_headers = build_fetch_headers(state)
        fetch_started = utc_now()
        fetch_used_conditional = bool(req_headers)

        try:
            result = client.fetch(url, headers=req_headers or None)
        except Exception as exc:
            record_fetch_exception(
                part_entry=part_entry,
                summary=summary,
                log_event=log_event,
                source=source,
                run_id=run_id,
                part_type=part_type,
                url=url,
                fetch_started_at=fetch_started.isoformat(),
                used_conditional_headers=fetch_used_conditional,
                exc=exc,
            )
            rc = 2
            continue

        baseline_success = bool(state is not None and state.last_success_at is not None)
        no_change_reason: str | None = None

        if result.status_code == 304 and not baseline_success:
            result = client.fetch(url, headers=None)
            fetch_used_conditional = False

        content_sha256 = calculate_content_sha256(result.text) if result.status_code == 200 else None
        no_change_reason = compute_no_change_reason(
            status_code=int(result.status_code),
            baseline_success=baseline_success,
            previous_sha256=str(state.content_sha256) if state is not None and state.content_sha256 else None,
            content_sha256=content_sha256,
        )

        etag = header_value(result.headers, "etag")
        last_modified = header_value(result.headers, "last-modified")
        now = utc_now()

        part_entry["fetch"] = build_fetch_payload(
            started_at=fetch_started.isoformat(),
            fetched_at=now.isoformat(),
            status_code=int(result.status_code),
            final_url=str(result.final_url),
            etag=etag,
            last_modified=last_modified,
            content_sha256=content_sha256,
            used_conditional_headers=fetch_used_conditional,
            request_headers=req_headers,
        )

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
            apply_unexpected_fetch_status(
                part_entry=part_entry,
                summary=summary,
                part_type=part_type,
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
            )
            rc = 2
            continue

        if result.status_code == 200:
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            part_entry["snapshot_dir"] = str(snapshot_dir)
            write_fetch_snapshot_artifacts(
                snapshot_dir=snapshot_dir,
                result_text=result.text,
                retrieved_at_utc=now.strftime("%Y%m%dT%H%M%SZ"),
                url=url,
                final_url=str(result.final_url),
                status_code=int(result.status_code),
                content_sha256=content_sha256,
                headers=dict(result.headers),
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
            apply_no_change_outcome(
                part_entry=part_entry,
                summary=summary,
                log_event=log_event,
                source=source,
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
