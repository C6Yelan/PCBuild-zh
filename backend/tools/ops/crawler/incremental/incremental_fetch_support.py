"""Shared helpers for incremental fetch phase bookkeeping."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from backend.tools.crawler.io.artifact_io import write_json_file


def build_fetch_part_entry(part_type: str, url: str) -> dict[str, Any]:
    return {
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


def record_fetch_exception(
    *,
    part_entry: dict[str, Any],
    summary: dict[str, Any],
    log_event: Callable[..., None],
    source: str,
    run_id: str,
    part_type: str,
    url: str,
    fetch_started_at: str,
    used_conditional_headers: bool,
    exc: Exception,
) -> None:
    part_entry["status"] = "fetch_error"
    part_entry["fetch"] = {
        "started_at": fetch_started_at,
        "error": str(exc),
        "exc_type": type(exc).__name__,
        "used_conditional_headers": used_conditional_headers,
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
        used_conditional_headers=used_conditional_headers,
        error=str(exc),
        exc_type=type(exc).__name__,
    )


def compute_no_change_reason(
    *,
    status_code: int,
    baseline_success: bool,
    previous_sha256: str | None,
    content_sha256: str | None,
) -> str | None:
    if status_code == 304:
        return "http_304"
    if (
        status_code == 200
        and baseline_success
        and previous_sha256
        and content_sha256
        and str(previous_sha256) == str(content_sha256)
    ):
        return "content_sha256_same"
    return None


def build_fetch_payload(
    *,
    started_at: str,
    fetched_at: str,
    status_code: int,
    final_url: str,
    etag: str | None,
    last_modified: str | None,
    content_sha256: str | None,
    used_conditional_headers: bool,
    request_headers: dict[str, str],
) -> dict[str, Any]:
    return {
        "started_at": started_at,
        "fetched_at": fetched_at,
        "status_code": status_code,
        "final_url": final_url,
        "etag": etag,
        "last_modified": last_modified,
        "content_sha256": content_sha256,
        "used_conditional_headers": used_conditional_headers,
        "request_headers": dict(request_headers),
    }


def write_fetch_snapshot_artifacts(
    *,
    snapshot_dir: Path,
    result_text: str,
    retrieved_at_utc: str,
    url: str,
    final_url: str,
    status_code: int,
    content_sha256: str | None,
    headers: dict[str, Any],
) -> None:
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    (snapshot_dir / "body.txt").write_text(result_text, encoding="utf-8", errors="replace")
    write_json_file(
        snapshot_dir / "meta.json",
        {
            "retrieved_at_utc": retrieved_at_utc,
            "url": url,
            "final_url": final_url,
            "status_code": status_code,
            "content_sha256": content_sha256,
            "headers": headers,
        },
    )


def apply_unexpected_fetch_status(
    *,
    part_entry: dict[str, Any],
    summary: dict[str, Any],
    part_type: str,
    status_code: int,
) -> None:
    part_entry["status"] = "fetch_error"
    summary["counts"]["parts_failed"] += 1
    summary["errors"].append(
        f"unexpected_status[{part_type}]: status_code={status_code}"
    )


def apply_no_change_outcome(
    *,
    part_entry: dict[str, Any],
    summary: dict[str, Any],
    log_event: Callable[..., None],
    source: str,
    run_id: str,
    part_type: str,
    reason: str,
    status_code: int,
) -> None:
    part_entry["status"] = "no_change"
    part_entry["no_change"] = True
    part_entry["skip_reason"] = reason
    summary["counts"]["parts_no_change"] += 1
    log_event(
        event="t10_no_change",
        source=source,
        stage="fetch",
        run_id=run_id,
        part_type=part_type,
        reason=reason,
        status_code=status_code,
    )


__all__ = [
    "apply_no_change_outcome",
    "apply_unexpected_fetch_status",
    "build_fetch_part_entry",
    "build_fetch_payload",
    "compute_no_change_reason",
    "record_fetch_exception",
    "write_fetch_snapshot_artifacts",
]
