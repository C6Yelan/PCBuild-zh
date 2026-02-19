# backend/tools/crawl_parse_snapshot.py
from __future__ import annotations

import argparse
from collections import Counter
import json
import logging
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.obs_events import ensure_cli_logging, log_loki_event
from backend.services.crawler.sources import SourceId
from backend.services.crawler.parsers import get_listing_parser
from backend.services.crawler.schema_gate.validate import SchemaGateError, validate_payload_fail_fast
from backend.services.crawler.dq_gate import run_dq_gate
from backend.tools.crawler.link_consistency_check_json import main as run_link_consistency_check_json

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


def _get_env() -> str:
    return os.getenv("APP_ENV") or os.getenv("ENV") or "prod"


def _write_json_atomic(path: Path, obj: Any) -> None:
    """
    原子寫入：先寫到同資料夾的 tmp，再用 os.replace 覆蓋目標檔，避免中途失敗留下半截檔。
    注意：tmp 必須在同一個資料夾/檔案系統上，replace 才能達成原子替換語意。
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"invalid JSONL at line {lineno}: {e.msg}") from e
            if not isinstance(row, dict):
                raise ValueError(f"expected object at line {lineno}, got {type(row).__name__}")
            rows.append(row)
    return rows


def _build_t5_summary(reports: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter(str(rep.get("status", "")) for rep in reports)
    reason_counts = Counter(str(rep.get("reason_code", "")) for rep in reports)
    non_match = sum(1 for rep in reports if rep.get("status") != "match")
    return {
        "total": len(reports),
        "non_match": non_match,
        "status_counts": dict(sorted(status_counts.items())),
        "reason_counts": dict(sorted(reason_counts.items())),
    }


def _coerce_t5_input_item(item: Any, *, source: str) -> dict[str, Any]:
    if isinstance(item, dict):
        out = dict(item)
    elif hasattr(item, "model_dump") and callable(getattr(item, "model_dump")):
        dumped = item.model_dump()
        if not isinstance(dumped, dict):
            raise ValueError(f"T5 item model_dump() must return dict, got {type(dumped).__name__}")
        out = dict(dumped)
    elif hasattr(item, "__dict__"):
        out = dict(vars(item))
    else:
        raise ValueError(f"T5 item must be dict-like, got {type(item).__name__}")

    if "source" not in out:
        out["source"] = source
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, choices=[s.value for s in SourceId])
    ap.add_argument("--snapshot-dir", required=True, help="包含 meta.json 與 body.txt 的資料夾")
    ap.add_argument("--run-id", default=None, help="(optional) pipeline run_id for observability correlation")
    ap.add_argument(
        "--dq-outdir",
        default=None,
        help="(optional) 落檔 DQ 產物：dq_report.json / dq_pass.json / dq_quarantine.json",
    )
    ap.add_argument("--t5-outdir", default=None, help="(optional) 啟用 T5 並將輸出落檔到此資料夾")
    ap.add_argument("--t5-limit", default=0, type=int, help="(optional) 只檢查前 N 筆，N<=0 代表全量")
    ap.add_argument("--t5-min-interval-ms", default=1500, type=int)
    ap.add_argument("--t5-timeout-s", default=10, type=float)
    ap.add_argument("--t5-max-redirects", default=5, type=int)
    ap.add_argument("--t5-max-bytes", default=4194304, type=int)
    ap.add_argument("--t5-block-pattern", action="append", default=[])
    args = ap.parse_args()
    ensure_cli_logging(logger=_PIPELINE_LOGGER)
    app_git_sha = (os.getenv("APP_GIT_SHA") or "unknown").strip() or "unknown"
    src = str(args.source)

    snap = Path(args.snapshot_dir).resolve()
    meta = json.loads((snap / "meta.json").read_text(encoding="utf-8"))
    html = (snap / "body.txt").read_text(encoding="utf-8", errors="replace")

    parser = get_listing_parser(SourceId(args.source))
    items = parser.parse_listings(html=html, page_url=meta.get("final_url") or meta["url"])
    payload = [item.__dict__ for item in items]

    # T3: schema gate
    try:
        validate_payload_fail_fast(source_id=args.source, payload=payload)
    except SchemaGateError as e:
        print(json.dumps(e.report, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2

    # T4: DQ gate
    dq = run_dq_gate(payload)
    rep = dq.report

    # stderr：結構化一行 log（不污染 stdout JSON）
    print(
        "category=dq event=dq_gate_result part=%s total=%d passed=%d quarantined=%d errors=%d warnings=%d infos=%d snapshot_dir=%s"
        % (
            rep.category,
            rep.total,
            rep.passed,
            rep.quarantined,
            rep.errors,
            rep.warnings,
            rep.infos,
            str(snap),
        ),
        file=sys.stderr,
    )

    # 落檔（無論成功/失敗都落，方便追查）
    if args.dq_outdir:
        outdir = Path(args.dq_outdir).resolve()
        _write_json_atomic(outdir / "dq_report.json", rep.to_dict())
        _write_json_atomic(outdir / "dq_pass.json", dq.passed_items)
        _write_json_atomic(outdir / "dq_quarantine.json", dq.quarantined_items)

    # fail-fast：error-level findings 就阻斷
    if rep.errors > 0:
        print(json.dumps(rep.to_dict(), ensure_ascii=False, indent=2), file=sys.stderr)
        return 2

    # Optional T5 gate: only runs when t5_outdir is explicitly provided.
    if args.t5_outdir:
        t5_t0 = time.monotonic()
        outdir = Path(args.t5_outdir).resolve()
        outdir.mkdir(parents=True, exist_ok=True)

        dq_ok_items = dq.passed_items
        if args.t5_limit and args.t5_limit > 0:
            t5_items = dq_ok_items[: args.t5_limit]
        else:
            t5_items = dq_ok_items

        log_loki_event(
            _PIPELINE_LOGGER,
            event="t5_link_started",
            source=src,
            stage="t5_link",
            env=_get_env(),
            gate_name="t5_link",
            run_id=args.run_id,
            app_git_sha=app_git_sha,
            snapshot_dir=str(snap),
            t5_outdir=str(outdir),
            input_total=int(len(t5_items)),
            min_interval_ms=int(args.t5_min_interval_ms),
            timeout_s=float(args.t5_timeout_s),
            max_redirects=int(args.t5_max_redirects),
            max_bytes=int(args.t5_max_bytes),
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        t5_input_path = outdir / "t5.input.json"
        t5_report_path = outdir / "t5.link_report.jsonl"
        t5_summary_path = outdir / "t5.summary.json"
        t5_passed_path = outdir / "t5.passed.json"
        t5_quarantine_path = outdir / "t5.quarantine.json"

        # link_consistency_check_json 會逐筆解析 required field "source"，因此這裡需補齊每筆 source。
        try:
            t5_input_items = [_coerce_t5_input_item(item, source=str(args.source)) for item in t5_items]
        except ValueError as e:
            log_loki_event(
                _PIPELINE_LOGGER,
                level=logging.ERROR,
                event="t5_link_failed",
                source=src,
                stage="t5_link",
                env=_get_env(),
                gate_name="t5_link",
                run_id=args.run_id,
                app_git_sha=app_git_sha,
                snapshot_dir=str(snap),
                t5_outdir=str(outdir),
                input_total=int(len(t5_items)),
                error=str(e),
                exc_type=type(e).__name__,
                elapsed_ms=int((time.monotonic() - t5_t0) * 1000),
                ended_at=datetime.now(timezone.utc).isoformat(),
            )
            print(f"T5 input error: {e}", file=sys.stderr)
            return 2

        _write_json_atomic(t5_input_path, t5_input_items)

        t5_argv = [
            "--input",
            str(t5_input_path),
            "--output",
            str(t5_report_path),
            "--min-interval-ms",
            str(args.t5_min_interval_ms),
            "--timeout-s",
            str(args.t5_timeout_s),
            "--max-redirects",
            str(args.t5_max_redirects),
            "--max-bytes",
            str(args.t5_max_bytes),
        ]
        for p in args.t5_block_pattern:
            t5_argv.extend(["--block-pattern", p])

        t5_rc = run_link_consistency_check_json(t5_argv)
        if t5_rc != 0:
            log_loki_event(
                _PIPELINE_LOGGER,
                level=logging.ERROR,
                event="t5_link_failed",
                source=src,
                stage="t5_link",
                env=_get_env(),
                gate_name="t5_link",
                run_id=args.run_id,
                app_git_sha=app_git_sha,
                snapshot_dir=str(snap),
                t5_outdir=str(outdir),
                input_total=int(len(t5_items)),
                t5_rc=int(t5_rc),
                error=f"link_consistency_check_json failed rc={t5_rc}",
                exc_type="SystemExit",
                elapsed_ms=int((time.monotonic() - t5_t0) * 1000),
                ended_at=datetime.now(timezone.utc).isoformat(),
            )
            return 2

        try:
            reports = _read_jsonl(t5_report_path)
        except (OSError, ValueError) as e:
            log_loki_event(
                _PIPELINE_LOGGER,
                level=logging.ERROR,
                event="t5_link_failed",
                source=src,
                stage="t5_link",
                env=_get_env(),
                gate_name="t5_link",
                run_id=args.run_id,
                app_git_sha=app_git_sha,
                snapshot_dir=str(snap),
                t5_outdir=str(outdir),
                input_total=int(len(t5_items)),
                error=str(e),
                exc_type=type(e).__name__,
                elapsed_ms=int((time.monotonic() - t5_t0) * 1000),
                ended_at=datetime.now(timezone.utc).isoformat(),
            )
            print(f"T5 output error: {e}", file=sys.stderr)
            return 2

        if len(reports) != len(t5_items):
            msg = "T5 output error: report/input length mismatch report=%d input=%d" % (len(reports), len(t5_items))
            log_loki_event(
                _PIPELINE_LOGGER,
                level=logging.ERROR,
                event="t5_link_failed",
                source=src,
                stage="t5_link",
                env=_get_env(),
                gate_name="t5_link",
                run_id=args.run_id,
                app_git_sha=app_git_sha,
                snapshot_dir=str(snap),
                t5_outdir=str(outdir),
                input_total=int(len(t5_items)),
                report_total=int(len(reports)),
                error=msg,
                exc_type="ValueError",
                elapsed_ms=int((time.monotonic() - t5_t0) * 1000),
                ended_at=datetime.now(timezone.utc).isoformat(),
            )
            print(
                msg,
                file=sys.stderr,
            )
            return 2

        t5_passed: list[dict[str, Any]] = []
        t5_quarantine: list[dict[str, Any]] = []
        for item, report in zip(t5_items, reports):
            if report.get("status") == "match":
                t5_passed.append(item)
            else:
                t5_quarantine.append(item)

        summary = _build_t5_summary(reports)
        _write_json_atomic(t5_summary_path, summary)
        _write_json_atomic(t5_passed_path, t5_passed)
        _write_json_atomic(t5_quarantine_path, t5_quarantine)

        print(
            "T5 status_counts=%s reason_counts=%s outdir=%s"
            % (summary["status_counts"], summary["reason_counts"], str(outdir)),
            file=sys.stderr,
        )

        non_match = int(summary["non_match"])
        status = "succeeded" if non_match == 0 else "completed_with_mismatch"
        log_loki_event(
            _PIPELINE_LOGGER,
            event="t5_link_finished",
            source=src,
            stage="t5_link",
            env=_get_env(),
            gate_name="t5_link",
            run_id=args.run_id,
            app_git_sha=app_git_sha,
            snapshot_dir=str(snap),
            t5_outdir=str(outdir),
            status=status,
            input_total=int(len(t5_items)),
            report_total=int(len(reports)),
            matched_total=int(len(t5_passed)),
            non_match_total=non_match,
            elapsed_ms=int((time.monotonic() - t5_t0) * 1000),
            ended_at=datetime.now(timezone.utc).isoformat(),
        )

        # Keep stdout as match-only items even when gate fails, so consumers never receive non-match rows.
        print(json.dumps(t5_passed, ensure_ascii=False, indent=2))
        if summary["non_match"] > 0:
            return 2
        return 0

    # stdout：只輸出 pass（讓你原本的 `> temp/零件.json` 照舊可用）
    print(json.dumps(dq.passed_items, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
