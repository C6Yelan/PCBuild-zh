# backend/tools/ops/crawler/incremental/incremental_publish_execution.py
"""Merge and publish execution helpers for incremental crawler runs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from backend.tools.db.merge_from_staging_cli import main as merge_from_staging_main

from .incremental_parsing import extract_last_json_object, parse_merge_counts
from .incremental_subprocess import run_cli_main, write_text_file
from ..publication.publish_publication_cli import main as publish_publication_main


def run_merge_and_publish(
    *,
    source: str,
    run_id: str,
    run_dir: Path,
    changed_parts: list[dict[str, Any]],
    publish_enabled: bool,
    summary: dict[str, Any],
    log_event: Callable[..., None],
) -> int:
    merge_argv = ["--run-id", run_id]
    merge_rc, merge_stdout, merge_stderr = run_cli_main(merge_from_staging_main, merge_argv)
    merge_logs = run_dir / "logs"
    write_text_file(merge_logs / "t8_merge.stdout.log", merge_stdout)
    write_text_file(merge_logs / "t8_merge.stderr.log", merge_stderr)
    merge_counts = parse_merge_counts(merge_stdout + "\n" + merge_stderr) or {}

    summary["merge"] = {
        "rc": int(merge_rc),
        "counts": merge_counts,
        "stdout_log": str(merge_logs / "t8_merge.stdout.log"),
        "stderr_log": str(merge_logs / "t8_merge.stderr.log"),
    }
    log_event(
        event="t10_merge_done",
        source=source,
        stage="merge",
        run_id=run_id,
        part_type="all",
        rc=int(merge_rc),
        changed_part_total=int(len(changed_parts)),
        **merge_counts,
    )

    if merge_rc != 0:
        summary["errors"].append(f"merge_failed: rc={merge_rc}")
        return 2

    if not publish_enabled:
        summary["publish"] = {"rc": 0, "published": False, "reason": "publish_disabled"}
        log_event(
            event="t10_publish_done",
            source=source,
            stage="publish",
            run_id=run_id,
            part_type="all",
            rc=0,
            published=False,
            reason="publish_disabled",
        )
        return 0

    pub_argv = ["--run-id", run_id]
    pub_rc, pub_stdout, pub_stderr = run_cli_main(publish_publication_main, pub_argv)
    write_text_file(merge_logs / "t9_publish.stdout.log", pub_stdout)
    write_text_file(merge_logs / "t9_publish.stderr.log", pub_stderr)
    pub_obj = extract_last_json_object(pub_stdout) or {}

    summary["publish"] = {
        "rc": int(pub_rc),
        "published": bool(pub_obj.get("published") or pub_obj.get("ok")),
        "stdout_log": str(merge_logs / "t9_publish.stdout.log"),
        "stderr_log": str(merge_logs / "t9_publish.stderr.log"),
        "result": pub_obj,
    }
    log_event(
        event="t10_publish_done",
        source=source,
        stage="publish",
        run_id=run_id,
        part_type="all",
        rc=int(pub_rc),
        published=bool(pub_obj.get("published") or pub_obj.get("ok")),
    )

    if pub_rc != 0:
        summary["errors"].append(f"publish_failed: rc={pub_rc}")
        return 2
    return 0


__all__ = [
    "run_merge_and_publish",
]
