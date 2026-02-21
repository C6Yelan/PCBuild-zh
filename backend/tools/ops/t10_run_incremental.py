# backend/tools/ops/t10_run_incremental.py
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from sqlalchemy.orm import Session

from backend.core.obs_events import ensure_cli_logging, log_loki_event
from backend.db import SessionLocal
from backend.services.crawler import CrawlerHttpClient, CrawlerSettings
from backend.services.crawler.fetch_state_repo import get_fetch_state, upsert_fetch_state
from backend.services.crawler.part_registry import resolve_source_parts
from backend.tools.crawler.crawl_parse_snapshot import main as crawl_parse_main
from backend.tools.db.t7_stage_from_snapshot import main as t7_stage_main
from backend.tools.db.t8_merge_from_staging import main as t8_merge_main
from backend.tools.ops.t9_publish_publication import main as t9_publish_main

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")
_T8_COUNTS_RE = re.compile(
    r"items\(pass\)=(?P<items>\d+)\s+product_upsert=(?P<product>\d+)\s+price_upsert=(?P<price>\d+)\s+spec_upsert=(?P<spec>\d+)"
)


def _get_env() -> str:
    return os.getenv("APP_ENV") or os.getenv("ENV") or "prod"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _header_value(headers: Any, name: str) -> str | None:
    target = name.lower()
    for k, v in dict(headers).items():
        if str(k).lower() == target:
            return str(v)
    return None


def _run_cli_main(main_fn: Callable[[], int], argv: list[str]) -> tuple[int, str, str]:
    old_argv = sys.argv[:]
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    try:
        sys.argv = [getattr(main_fn, "__name__", "cli")] + argv
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            try:
                ret = main_fn()
                rc = int(ret) if ret is not None else 0
            except SystemExit as e:
                rc = int(e.code) if isinstance(e.code, int) else 1
        return rc, out_buf.getvalue(), err_buf.getvalue()
    finally:
        sys.argv = old_argv


def _extract_last_json_object(text: str) -> dict[str, Any] | None:
    for line in reversed(text.splitlines()):
        s = line.strip()
        if not s.startswith("{") or not s.endswith("}"):
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def _extract_json_array(text: str) -> list[dict[str, Any]] | None:
    stripped = text.strip()
    if not stripped:
        return []

    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, list):
            return [x for x in parsed if isinstance(x, dict)]
    except json.JSONDecodeError:
        pass

    start = stripped.find("[")
    end = stripped.rfind("]")
    if start >= 0 and end > start:
        frag = stripped[start : end + 1]
        try:
            parsed = json.loads(frag)
            if isinstance(parsed, list):
                return [x for x in parsed if isinstance(x, dict)]
        except json.JSONDecodeError:
            return None
    return None


def _parse_t8_counts(text: str) -> dict[str, int] | None:
    m = _T8_COUNTS_RE.search(text)
    if not m:
        return None
    return {
        "items_pass": int(m.group("items")),
        "product_upsert": int(m.group("product")),
        "price_upsert": int(m.group("price")),
        "spec_upsert": int(m.group("spec")),
    }


def _build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="T10: run incremental refresh (fetch -> parse/gates -> stage -> merge -> publish)"
    )
    ap.add_argument("--source", required=True, help="crawler source id, e.g. coolpc")
    ap.add_argument("--parts", default="all", help="comma-separated part list, default: all")
    ap.add_argument("--dry-run", action="store_true", help="do not write DB and do not publish")

    pub_group = ap.add_mutually_exclusive_group()
    pub_group.add_argument("--publish", dest="publish", action="store_true", help="publish to pointer after merge")
    pub_group.add_argument("--no-publish", dest="publish", action="store_false", help="skip publish (default)")
    ap.set_defaults(publish=False)

    ap.add_argument("--max-items", type=int, default=0, help="per-part protection cap; <=0 means unlimited")
    return ap


def _log_event(
    *,
    event: str,
    source: str,
    stage: str,
    run_id: str,
    part_type: str | None = None,
    **fields: Any,
) -> None:
    extra = dict(fields)
    if part_type is not None:
        extra["part_type"] = part_type
    log_loki_event(
        _PIPELINE_LOGGER,
        event=event,
        source=source,
        stage=stage,
        env=_get_env(),
        run_id=run_id,
        **extra,
    )


def _build_fetch_headers(state: Any) -> dict[str, str]:
    headers: dict[str, str] = {}
    if state is None:
        return headers
    if state.etag:
        headers["If-None-Match"] = str(state.etag)
    if state.last_modified:
        headers["If-Modified-Since"] = str(state.last_modified)
    return headers


def _record_fetch_state(
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
        updated_at=_utc_now(),
    )
    db.commit()


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    if int(args.max_items) < 0:
        raise SystemExit("--max-items must be >= 0")

    src = str(args.source).strip().lower()
    dry_run = bool(args.dry_run)
    publish_requested = bool(args.publish)
    publish_enabled = bool(args.publish and not dry_run)

    ensure_cli_logging(logger=_PIPELINE_LOGGER)

    run_id = str(uuid4())
    run_dir = (Path("temp") / "t10" / run_id).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    summary_path = run_dir / "summary.json"

    started_at = _utc_now()
    summary: dict[str, Any] = {
        "run_id": run_id,
        "source": src,
        "dry_run": dry_run,
        "publish_requested": publish_requested,
        "publish_enabled": publish_enabled,
        "max_items": int(args.max_items),
        "parts_requested": [],
        "parts": [],
        "counts": {
            "parts_total": 0,
            "parts_changed": 0,
            "parts_no_change": 0,
            "parts_failed": 0,
        },
        "merge": None,
        "publish": None,
        "errors": [],
        "started_at": started_at.isoformat(),
    }

    rc = 0

    try:
        try:
            targets = resolve_source_parts(src, args.parts)
            summary["parts_requested"] = [p for p, _ in targets]
            summary["counts"]["parts_total"] = len(targets)
        except Exception as e:
            summary["errors"].append(f"resolve_parts_failed: {e}")
            targets = []
            rc = 2

        if publish_requested and dry_run:
            summary["errors"].append("publish_ignored_in_dry_run")

        _log_event(
            event="t10_start",
            source=src,
            stage="incremental",
            run_id=run_id,
            part_total=int(summary["counts"]["parts_total"]),
            dry_run=dry_run,
            publish_enabled=publish_enabled,
            max_items=int(args.max_items),
            requested_parts=summary["parts_requested"],
        )

        changed_parts: list[dict[str, Any]] = []

        if targets:
            with SessionLocal() as db:
                with CrawlerHttpClient(CrawlerSettings()) as client:
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

                        state = get_fetch_state(db, source=src, part_type=part_type, url=url)
                        req_headers = _build_fetch_headers(state)
                        fetch_started = _utc_now()
                        fetch_used_conditional = bool(req_headers)

                        try:
                            result = client.fetch(url, headers=req_headers or None)
                        except Exception as e:
                            part_entry["status"] = "fetch_error"
                            part_entry["fetch"] = {
                                "started_at": fetch_started.isoformat(),
                                "error": str(e),
                                "exc_type": type(e).__name__,
                                "used_conditional_headers": fetch_used_conditional,
                            }
                            summary["counts"]["parts_failed"] += 1
                            summary["errors"].append(f"fetch_failed[{part_type}]: {e}")
                            _log_event(
                                event="t10_fetch",
                                source=src,
                                stage="fetch",
                                run_id=run_id,
                                part_type=part_type,
                                url=url,
                                status="error",
                                used_conditional_headers=fetch_used_conditional,
                                error=str(e),
                                exc_type=type(e).__name__,
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
                        now = _utc_now()

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

                        _log_event(
                            event="t10_fetch",
                            source=src,
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
                            _record_fetch_state(
                                db,
                                dry_run=dry_run,
                                source=src,
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
                            _write_json(
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

                        _record_fetch_state(
                            db,
                            dry_run=dry_run,
                            source=src,
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
                            _log_event(
                                event="t10_no_change",
                                source=src,
                                stage="fetch",
                                run_id=run_id,
                                part_type=part_type,
                                reason=no_change_reason,
                                status_code=int(result.status_code),
                            )
                            _record_fetch_state(
                                db,
                                dry_run=dry_run,
                                source=src,
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

        if changed_parts:
            if dry_run:
                for part in changed_parts:
                    part_type = str(part["part_type"])
                    snapshot_dir = str(part["snapshot_dir"])
                    part_entry = part["entry_ref"]
                    part_logs = run_dir / "parts" / part_type / "logs"

                    parse_argv = [
                        "--source",
                        src,
                        "--snapshot-dir",
                        snapshot_dir,
                        "--run-id",
                        run_id,
                        "--dq-outdir",
                        str(run_dir / "parts" / part_type / "dq"),
                    ]
                    parse_rc, parse_stdout, parse_stderr = _run_cli_main(crawl_parse_main, parse_argv)
                    _write_text(part_logs / "parse.stdout.log", parse_stdout)
                    _write_text(part_logs / "parse.stderr.log", parse_stderr)

                    parsed_items = _extract_json_array(parse_stdout)
                    item_total = int(len(parsed_items)) if isinstance(parsed_items, list) else 0
                    over_limit = bool(args.max_items > 0 and item_total > int(args.max_items))

                    part_entry["parse"] = {
                        "rc": int(parse_rc),
                        "item_total": item_total,
                        "over_limit": over_limit,
                        "stdout_log": str(part_logs / "parse.stdout.log"),
                        "stderr_log": str(part_logs / "parse.stderr.log"),
                    }

                    _log_event(
                        event="t10_parse_done",
                        source=src,
                        stage="parse",
                        run_id=run_id,
                        part_type=part_type,
                        rc=int(parse_rc),
                        item_total=item_total,
                        over_limit=over_limit,
                    )

                    if parse_rc != 0 or over_limit:
                        part_entry["status"] = "parse_failed"
                        summary["counts"]["parts_failed"] += 1
                        if over_limit:
                            summary["errors"].append(
                                f"max_items_exceeded[{part_type}]: item_total={item_total} max_items={args.max_items}"
                            )
                        else:
                            summary["errors"].append(f"parse_failed[{part_type}]: rc={parse_rc}")
                        rc = 2
                    else:
                        part_entry["status"] = "parsed"

                summary["merge"] = {"rc": 0 if rc == 0 else None, "reason": "skipped_dry_run"}
                summary["publish"] = {
                    "rc": 0 if rc == 0 else None,
                    "published": False,
                    "reason": "skipped_dry_run",
                }
                _log_event(
                    event="t10_merge_done",
                    source=src,
                    stage="merge",
                    run_id=run_id,
                    part_type="all",
                    rc=0 if rc == 0 else 2,
                    changed_part_total=int(len(changed_parts)),
                    skipped=True,
                    reason="dry_run",
                )
                _log_event(
                    event="t10_publish_done",
                    source=src,
                    stage="publish",
                    run_id=run_id,
                    part_type="all",
                    rc=0 if rc == 0 else 2,
                    published=False,
                    reason="dry_run",
                )
            else:
                with SessionLocal() as db:
                    for part in changed_parts:
                        part_type = str(part["part_type"])
                        snapshot_dir = str(part["snapshot_dir"])
                        part_entry = part["entry_ref"]
                        part_logs = run_dir / "parts" / part_type / "logs"
                        part_t7_artifact_dir = run_dir / "parts" / part_type / "t7_artifacts"

                        stage_argv = [
                            "--source",
                            src,
                            "--snapshot-dir",
                            snapshot_dir,
                            "--run-id",
                            run_id,
                            "--artifact-dir",
                            str(part_t7_artifact_dir),
                        ]
                        stage_rc, stage_stdout, stage_stderr = _run_cli_main(t7_stage_main, stage_argv)
                        _write_text(part_logs / "stage.stdout.log", stage_stdout)
                        _write_text(part_logs / "stage.stderr.log", stage_stderr)

                        stage_obj = _extract_last_json_object(stage_stdout)
                        staged_total = 0
                        if isinstance(stage_obj, dict):
                            staged_total = int(stage_obj.get("item_inserted") or 0) + int(stage_obj.get("item_updated") or 0)

                        over_limit = bool(args.max_items > 0 and staged_total > int(args.max_items))
                        part_entry["parse"] = {
                            "rc": int(stage_rc),
                            "item_total": staged_total,
                            "over_limit": over_limit,
                            "note": "t7 stage includes parse/gates before DB write",
                        }
                        part_entry["stage"] = {
                            "rc": int(stage_rc),
                            "result": stage_obj,
                            "over_limit": over_limit,
                            "artifact_dir": str(part_t7_artifact_dir),
                            "stdout_log": str(part_logs / "stage.stdout.log"),
                            "stderr_log": str(part_logs / "stage.stderr.log"),
                        }

                        _log_event(
                            event="t10_parse_done",
                            source=src,
                            stage="parse",
                            run_id=run_id,
                            part_type=part_type,
                            rc=int(stage_rc),
                            item_total=staged_total,
                            over_limit=over_limit,
                        )
                        _log_event(
                            event="t10_stage_done",
                            source=src,
                            stage="stage",
                            run_id=run_id,
                            part_type=part_type,
                            rc=int(stage_rc),
                            item_total=staged_total,
                            item_inserted=int((stage_obj or {}).get("item_inserted") or 0),
                            item_updated=int((stage_obj or {}).get("item_updated") or 0),
                            gate_inserted=int((stage_obj or {}).get("gate_inserted") or 0),
                            gate_updated=int((stage_obj or {}).get("gate_updated") or 0),
                        )

                        if stage_rc != 0 or over_limit:
                            part_entry["status"] = "stage_failed"
                            summary["counts"]["parts_failed"] += 1
                            if over_limit:
                                summary["errors"].append(
                                    f"max_items_exceeded[{part_type}]: item_total={staged_total} max_items={args.max_items}"
                                )
                            else:
                                summary["errors"].append(f"stage_failed[{part_type}]: rc={stage_rc}")
                            rc = 2
                            continue

                        part_entry["status"] = "staged"
                        _record_fetch_state(
                            db,
                            dry_run=dry_run,
                            source=src,
                            part_type=part_type,
                            url=str(part["url"]),
                            etag=None,
                            last_modified=None,
                            content_sha256=None,
                            last_status_code=None,
                            last_success_at=_utc_now(),
                        )

                if rc == 0:
                    merge_argv = ["--run-id", run_id]
                    merge_rc, merge_stdout, merge_stderr = _run_cli_main(t8_merge_main, merge_argv)
                    merge_logs = run_dir / "logs"
                    _write_text(merge_logs / "t8_merge.stdout.log", merge_stdout)
                    _write_text(merge_logs / "t8_merge.stderr.log", merge_stderr)
                    merge_counts = _parse_t8_counts(merge_stdout + "\n" + merge_stderr) or {}
                    summary["merge"] = {
                        "rc": int(merge_rc),
                        "counts": merge_counts,
                        "stdout_log": str(merge_logs / "t8_merge.stdout.log"),
                        "stderr_log": str(merge_logs / "t8_merge.stderr.log"),
                    }

                    _log_event(
                        event="t10_merge_done",
                        source=src,
                        stage="merge",
                        run_id=run_id,
                        part_type="all",
                        rc=int(merge_rc),
                        changed_part_total=int(len(changed_parts)),
                        **merge_counts,
                    )

                    if merge_rc != 0:
                        summary["errors"].append(f"merge_failed: rc={merge_rc}")
                        rc = 2
                    elif publish_enabled:
                        pub_argv = ["--run-id", run_id]
                        pub_rc, pub_stdout, pub_stderr = _run_cli_main(t9_publish_main, pub_argv)
                        _write_text(merge_logs / "t9_publish.stdout.log", pub_stdout)
                        _write_text(merge_logs / "t9_publish.stderr.log", pub_stderr)
                        pub_obj = _extract_last_json_object(pub_stdout) or {}

                        summary["publish"] = {
                            "rc": int(pub_rc),
                            "published": bool(pub_obj.get("published") or pub_obj.get("ok")),
                            "stdout_log": str(merge_logs / "t9_publish.stdout.log"),
                            "stderr_log": str(merge_logs / "t9_publish.stderr.log"),
                            "result": pub_obj,
                        }

                        _log_event(
                            event="t10_publish_done",
                            source=src,
                            stage="publish",
                            run_id=run_id,
                            part_type="all",
                            rc=int(pub_rc),
                            published=bool(pub_obj.get("published") or pub_obj.get("ok")),
                        )

                        if pub_rc != 0:
                            summary["errors"].append(f"publish_failed: rc={pub_rc}")
                            rc = 2
                    else:
                        summary["publish"] = {"rc": 0, "published": False, "reason": "publish_disabled"}
                        _log_event(
                            event="t10_publish_done",
                            source=src,
                            stage="publish",
                            run_id=run_id,
                            part_type="all",
                            rc=0,
                            published=False,
                            reason="publish_disabled",
                        )
                else:
                    summary["merge"] = {"rc": None, "reason": "skipped_due_to_stage_errors"}
                    summary["publish"] = {"rc": None, "published": False, "reason": "skipped_due_to_errors"}
        else:
            skip_reason = "skipped_no_changed_parts" if rc == 0 else "skipped_due_to_errors"
            skip_rc = 0 if rc == 0 else 2
            summary["merge"] = {"rc": skip_rc, "reason": skip_reason}
            summary["publish"] = {"rc": skip_rc, "published": False, "reason": skip_reason}
            _log_event(
                event="t10_merge_done",
                source=src,
                stage="merge",
                run_id=run_id,
                part_type="all",
                rc=skip_rc,
                changed_part_total=0,
                skipped=True,
                reason=skip_reason,
            )
            _log_event(
                event="t10_publish_done",
                source=src,
                stage="publish",
                run_id=run_id,
                part_type="all",
                rc=skip_rc,
                published=False,
                reason=skip_reason,
            )
    except Exception as e:
        summary["errors"].append(f"unhandled_error: {e}")
        summary["errors"].append(f"exc_type: {type(e).__name__}")
        if summary["merge"] is None:
            summary["merge"] = {"rc": None, "reason": "skipped_due_to_errors"}
        if summary["publish"] is None:
            summary["publish"] = {"rc": None, "published": False, "reason": "skipped_due_to_errors"}
        rc = 2

    ended_at = _utc_now()
    summary["ended_at"] = ended_at.isoformat()
    summary["elapsed_ms"] = int((ended_at - started_at).total_seconds() * 1000)
    summary["exit_code"] = int(rc)
    _write_json(summary_path, summary)

    print(
        json.dumps(
            {
                "run_id": run_id,
                "summary_path": str(summary_path),
                "exit_code": int(rc),
                "changed_parts": int(summary["counts"]["parts_changed"]),
                "no_change_parts": int(summary["counts"]["parts_no_change"]),
            },
            ensure_ascii=False,
        )
    )
    return int(rc)


if __name__ == "__main__":
    raise SystemExit(main())
