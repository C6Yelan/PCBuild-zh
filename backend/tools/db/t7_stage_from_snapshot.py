# backend/tools/db/t7_stage_from_snapshot.py
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4
from hashlib import sha256

from sqlalchemy.orm import Session

from backend.db import SessionLocal
from backend.core.obs_events import ensure_cli_logging, log_loki_event
from backend.services.crawler.staging.repo import (
    create_ingest_run,
    upsert_stg_items,
    upsert_stg_gate_result,
)
from backend.tools.crawler.crawl_parse_snapshot import main as crawl_parse_main

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


def _get_env() -> str:
    return os.getenv("APP_ENV") or os.getenv("ENV") or "prod"


def _make_item_key(source: str, it: dict[str, Any]) -> str:
    seed = "|".join(
        [
            source,
            str(it.get("category") or ""),
            str(it.get("url") or ""),
            str(it.get("title") or ""),
            str(it.get("sku_hint") or ""),
        ]
    )
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()


def _run_crawl_and_capture(argv: list[str]) -> tuple[int, str, str]:
    """
    在同一個 process 呼叫 crawl_parse_snapshot.main()，
    用 redirect_stdout/redirect_stderr 捕捉輸出，避免污染外層 CLI。
    """
    old_argv = sys.argv[:]
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    try:
        sys.argv = ["crawl_parse_snapshot"] + argv
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            rc = crawl_parse_main()
        return int(rc), out_buf.getvalue(), err_buf.getvalue()
    finally:
        sys.argv = old_argv


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _file_meta(path: Path, *, base_dir: Path) -> dict[str, Any]:
    data = path.read_bytes()
    rel = str(path.relative_to(base_dir))
    st = path.stat()
    return {
        "relpath": rel,                    # 相對於 artifact_dir
        "sha256": sha256(data).hexdigest(),
        "bytes": int(st.st_size),
        "mtime": int(st.st_mtime),
    }



def main() -> int:
    ap = argparse.ArgumentParser(description="T7: stage from snapshot-dir (run crawl_parse_snapshot then ORM ingest)")
    ap.add_argument("--source", required=True)
    ap.add_argument("--snapshot-dir", required=True)
    ap.add_argument("--note", default=None)
    ap.add_argument("--run-id", default=None)
    ap.add_argument(
        "--artifact-dir",
        default=None,
        help="(optional) output dir for DQ/T5 artifacts; default temp/t7/<run_id>",
    )

    # 是否啟用 T5：crawl_parse_snapshot 是「有 t5-outdir 才會跑」
    ap.add_argument("--enable-t5", action="store_true")
    ap.add_argument("--t5-limit", default=0, type=int)
    ap.add_argument("--t5-min-interval-ms", default=1500, type=int)
    ap.add_argument("--t5-timeout-s", default=10.0, type=float)
    ap.add_argument("--t5-max-redirects", default=5, type=int)
    ap.add_argument("--t5-max-bytes", default=4194304, type=int)
    ap.add_argument("--t5-block-pattern", action="append", default=[])

    args = ap.parse_args()

    run_id: UUID = UUID(args.run_id) if args.run_id else uuid4()
    ensure_cli_logging(logger=_PIPELINE_LOGGER)
    src = str(args.source)
    app_git_sha = (os.getenv("APP_GIT_SHA") or "unknown").strip() or "unknown"
    artifact_dir = None
    t0 = time.monotonic()

    # run metadata: started
    log_loki_event(
        _PIPELINE_LOGGER,
        event="t7_stage_started",
        source=src,
        stage="stage",
        env=_get_env(),
        run_id=str(run_id),
        app_git_sha=app_git_sha,
        snapshot_dir=str(args.snapshot_dir),
        snapshot_name=str(Path(args.snapshot_dir).name),
        enable_t5=bool(args.enable_t5),
        t5_limit=int(args.t5_limit),
        t5_min_interval_ms=int(args.t5_min_interval_ms),
        t5_timeout_s=float(args.t5_timeout_s),
        t5_max_redirects=int(args.t5_max_redirects),
        t5_max_bytes=int(args.t5_max_bytes),
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    try:
        # 依你偏好：所有產物放 temp 下
        base_outdir = Path(args.artifact_dir).resolve() if args.artifact_dir else (Path("temp") / "t7" / str(run_id))
        artifact_dir = str(base_outdir)
        dq_outdir = base_outdir / "dq"
        t5_outdir = base_outdir / "t5" if args.enable_t5 else None

        crawl_argv = [
            "--source", args.source,
            "--snapshot-dir", args.snapshot_dir,
            "--dq-outdir", str(dq_outdir),
            "--run-id", str(run_id),
        ]

        if args.enable_t5 and t5_outdir is not None:
            crawl_argv += [
                "--t5-outdir", str(t5_outdir),
                "--t5-limit", str(args.t5_limit),
                "--t5-min-interval-ms", str(args.t5_min_interval_ms),
                "--t5-timeout-s", str(args.t5_timeout_s),
                "--t5-max-redirects", str(args.t5_max_redirects),
                "--t5-max-bytes", str(args.t5_max_bytes),
            ]
            for p in args.t5_block_pattern:
                crawl_argv += ["--t5-block-pattern", p]

        rc, stdout_txt, stderr_txt = _run_crawl_and_capture(crawl_argv)

        # crawl_parse_snapshot 設計：stdout 永遠只會是「通過的 items」
        items = []
        if stdout_txt.strip():
            parsed = json.loads(stdout_txt)
            if not isinstance(parsed, list):
                raise SystemExit("crawl_parse_snapshot stdout 不是 list JSON，無法入庫")
            items = parsed

        if not items:
            # run metadata: finished (no items / fail-fast)
            log_loki_event(
                _PIPELINE_LOGGER,
                level=logging.WARNING,
                event="t7_stage_finished",
                source=src,
                stage="stage",
                env=_get_env(),
                run_id=str(run_id),
                app_git_sha=app_git_sha,
                status="no_items",
                crawl_rc=int(rc),
                artifact_dir=artifact_dir,
                elapsed_ms=int((time.monotonic() - t0) * 1000),
                ended_at=datetime.now(timezone.utc).isoformat(),
            )
            # 沒 items 就不做 staging（通常是 T3/T4 fail-fast）
            # 將 stderr 原封不動印出，方便你追查
            sys.stderr.write(stderr_txt)
            return rc if rc != 0 else 2

        # Gate 摘要：從 dq_report / t5.summary 讀進來（若存在）
        dq_report_path = dq_outdir / "dq_report.json"
        dq_report = _load_json(dq_report_path) if dq_report_path.exists() else None
        dq_meta = _file_meta(dq_report_path, base_dir=base_outdir) if dq_report_path.exists() else None

        t5_summary = None
        t5_meta = None
        if t5_outdir is not None:
            t5_summary_path = t5_outdir / "t5.summary.json"
            if t5_summary_path.exists():
                t5_summary = _load_json(t5_summary_path)
                t5_meta = _file_meta(t5_summary_path, base_dir=base_outdir)

        # ORM 入庫：同一個交易（run + items + gate_results）
        with SessionLocal() as db:
            with db.begin():
                rid = create_ingest_run(db, source=args.source, note=args.note, run_id=run_id)
                inserted, updated = upsert_stg_items(db, run_id=rid, source=args.source, items=items)

                gate_inserted = 0
                gate_updated = 0

                for it in items:
                    url = str(it.get("url") or "")
                    item_key = _make_item_key(args.source, it)

                    # T4 DQ gate（成功才會有 items）
                    ins, upd = upsert_stg_gate_result(
                        db,
                        run_id=rid,
                        item_key=item_key,
                        gate_name="t4_dq",
                        status="pass",
                        detail_json={
                            "artifact_dir": str(base_outdir),
                            "snapshot_dir": str(Path(args.snapshot_dir).name),
                            "dq_report": dq_meta,
                            "dq_report_keys": list(dq_report.keys()) if isinstance(dq_report, dict) else None,
                        },
                    )
                    gate_inserted += ins
                    gate_updated += upd

                    # Optional T5 gate（如果 enable_t5）
                    if args.enable_t5:
                        # crawl_parse_snapshot：若有 non_match 會 return 2，但 stdout 仍是 match-only items
                        t5_status = "pass"
                        if rc != 0:
                            t5_status = "fail"
                        if isinstance(t5_summary, dict) and int(t5_summary.get("non_match") or 0) > 0:
                            t5_status = "fail"

                        ins2, upd2 = upsert_stg_gate_result(
                            db,
                            run_id=rid,
                            item_key=item_key,
                            gate_name="t5_link",
                            status=t5_status,
                            detail_json={
                                "artifact_dir": str(base_outdir),
                                "snapshot_dir": str(Path(args.snapshot_dir).name),
                                "t5_summary": t5_meta,
                                "t5_summary_keys": list(t5_summary.keys()) if isinstance(t5_summary, dict) else None,
                            },
                        )
                        gate_inserted += ins2
                        gate_updated += upd2

        # run metadata: finished (has items staged)
        status = "succeeded" if int(rc) == 0 else "completed_with_warnings"
        log_loki_event(
            _PIPELINE_LOGGER,
            event="t7_stage_finished",
            source=src,
            stage="stage",
            env=_get_env(),
            run_id=str(run_id),
            app_git_sha=app_git_sha,
            status=status,
            crawl_rc=int(rc),
            item_total=int(len(items)),
            item_inserted=int(inserted),
            item_updated=int(updated),
            gate_inserted=int(gate_inserted),
            gate_updated=int(gate_updated),
            artifact_dir=artifact_dir,
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            ended_at=datetime.now(timezone.utc).isoformat(),
        )

        print(
            json.dumps(
                {
                    "run_id": str(run_id),
                    "crawl_rc": rc,
                    "item_inserted": inserted,
                    "item_updated": updated,
                    "gate_inserted": gate_inserted,
                    "gate_updated": gate_updated,
                    "artifact_dir": str(base_outdir),
                },
                ensure_ascii=False,
            )
        )

        # 保留 crawl rc，讓 pipeline 能知道是否有 T5 non_match 等問題
        return rc
    except (Exception, SystemExit) as e:
        log_loki_event(
            _PIPELINE_LOGGER,
            level=logging.ERROR,
            event="t7_stage_failed",
            source=src,
            stage="stage",
            env=_get_env(),
            run_id=str(run_id),
            app_git_sha=app_git_sha,
            snapshot_dir=str(args.snapshot_dir),
            artifact_dir=artifact_dir,
            error=str(e),
            exc_type=type(e).__name__,
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            ended_at=datetime.now(timezone.utc).isoformat(),
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
