# backend/tools/crawler/parse/cli.py
from __future__ import annotations

import argparse
import logging

from backend.core.obs_events import ensure_cli_logging
from backend.services.crawler.schema_gate.validate import SchemaGateError
from backend.services.crawler.sources import SourceId
from backend.services.crawler.staging.conventions import get_app_git_sha
from backend.tools.crawler.parse.artifacts import (
    resolve_t5_artifact_paths,
    write_dq_artifacts,
    write_t5_outputs,
)
from backend.tools.crawler.parse.gate_execution import (
    T5GateConfig,
    run_dq_pipeline,
    run_t5_gate,
    validate_schema_payload,
)
from backend.tools.crawler.parse.output import (
    emit_dq_fail_fast,
    emit_dq_gate_result,
    emit_schema_gate_error,
    emit_stderr,
    emit_stdout_items,
    emit_t5_status,
)
from backend.tools.crawler.parse.pipeline import load_snapshot_payload

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


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
    ap.add_argument(
        "--t5-outdir",
        default=None,
        help="(optional) 啟用 link consistency 檢查並將輸出落檔到此資料夾",
    )
    ap.add_argument(
        "--t5-limit",
        default=0,
        type=int,
        help="(optional) link consistency 只檢查前 N 筆，N<=0 代表全量",
    )
    ap.add_argument("--t5-min-interval-ms", default=1500, type=int)
    ap.add_argument("--t5-timeout-s", default=10, type=float)
    ap.add_argument("--t5-max-redirects", default=5, type=int)
    ap.add_argument("--t5-max-bytes", default=4194304, type=int)
    ap.add_argument("--t5-block-pattern", action="append", default=[])
    args = ap.parse_args()
    ensure_cli_logging(logger=_PIPELINE_LOGGER)
    app_git_sha = get_app_git_sha()
    src = str(args.source)

    parsed_snapshot = load_snapshot_payload(source=args.source, snapshot_dir=args.snapshot_dir)

    try:
        validate_schema_payload(source=args.source, payload=parsed_snapshot.payload)
    except SchemaGateError as e:
        emit_schema_gate_error(e.report)
        return 2

    dq = run_dq_pipeline(parsed_snapshot.payload)
    rep = dq.report

    emit_dq_gate_result(report=rep, snapshot_dir=parsed_snapshot.snapshot_dir)

    if args.dq_outdir:
        write_dq_artifacts(
            outdir=args.dq_outdir,
            report=rep.to_dict(),
            passed_items=dq.passed_items,
            quarantined_items=dq.quarantined_items,
        )

    if rep.errors > 0:
        emit_dq_fail_fast(rep)
        return 2

    if args.t5_outdir:
        t5_artifacts = resolve_t5_artifact_paths(args.t5_outdir)
        t5_outcome = run_t5_gate(
            config=T5GateConfig(
                source=src,
                run_id=args.run_id,
                app_git_sha=app_git_sha,
                snapshot_dir=parsed_snapshot.snapshot_dir,
                artifacts=t5_artifacts,
                limit=int(args.t5_limit),
                min_interval_ms=int(args.t5_min_interval_ms),
                timeout_s=float(args.t5_timeout_s),
                max_redirects=int(args.t5_max_redirects),
                max_bytes=int(args.t5_max_bytes),
                block_patterns=[str(p) for p in args.t5_block_pattern],
            ),
            dq_passed_items=dq.passed_items,
            logger=_PIPELINE_LOGGER,
        )

        if t5_outcome.error_message is not None:
            emit_stderr(t5_outcome.error_message)
        if t5_outcome.summary is None:
            return int(t5_outcome.rc)

        write_t5_outputs(
            t5_artifacts,
            summary=t5_outcome.summary,
            passed_items=t5_outcome.passed_items,
            quarantined_items=t5_outcome.quarantined_items,
        )
        emit_t5_status(summary=t5_outcome.summary, outdir=t5_artifacts.outdir)
        emit_stdout_items(t5_outcome.passed_items)
        return int(t5_outcome.rc)

    emit_stdout_items(dq.passed_items)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
