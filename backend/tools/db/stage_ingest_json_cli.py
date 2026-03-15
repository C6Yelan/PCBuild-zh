# backend/tools/db/stage_ingest_json_cli.py
from __future__ import annotations

import argparse
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from backend.core.obs_events import ensure_cli_logging, log_loki_event
from backend.db import SessionLocal
from backend.services.crawler.staging.conventions import get_app_git_sha, get_crawler_env
from backend.tools.crawler.io.artifact_io import emit_json_stdout
from backend.tools.db.staging_ingest import load_stage_ingest_payload, stage_json_payload

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


def main() -> int:
    ap = argparse.ArgumentParser(description="T7: ingest canonical JSON into staging (ORM only)")
    ap.add_argument("--source", required=True, help="e.g. coolpc")
    ap.add_argument("--note", default=None)
    ap.add_argument("--input", required=True, help="JSON file path, or '-' for stdin")
    ap.add_argument("--run-id", default=None, help="optional UUID; else auto-generate")
    args = ap.parse_args()

    run_id: UUID = UUID(args.run_id) if args.run_id else uuid4()
    ensure_cli_logging(logger=_PIPELINE_LOGGER)

    src = str(args.source)
    input_name = "stdin" if args.input == "-" else Path(args.input).name
    app_git_sha = get_app_git_sha()
    item_total: int | None = None
    gate_total: int | None = None
    t0 = time.monotonic()

    try:
        payload = load_stage_ingest_payload(args.input)
        item_total = int(len(payload.items))
        gate_total = int(len(payload.gate_results))

        log_loki_event(
            _PIPELINE_LOGGER,
            event="t7_stage_ingest_started",
            source=src,
            stage="stage",
            env=get_crawler_env(),
            run_id=str(run_id),
            app_git_sha=app_git_sha,
            input=str(args.input),
            input_name=input_name,
            item_total=item_total,
            gate_total=gate_total,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        with SessionLocal() as db:
            staging_counts = stage_json_payload(
                db,
                source=src,
                note=args.note,
                run_id=run_id,
                payload=payload,
            )

        log_loki_event(
            _PIPELINE_LOGGER,
            event="t7_stage_ingest_finished",
            source=src,
            stage="stage",
            env=get_crawler_env(),
            run_id=str(run_id),
            app_git_sha=app_git_sha,
            input=str(args.input),
            input_name=input_name,
            item_total=item_total,
            gate_total=gate_total,
            item_inserted=int(staging_counts.item_inserted),
            item_updated=int(staging_counts.item_updated),
            gate_inserted=int(staging_counts.gate_inserted),
            gate_updated=int(staging_counts.gate_updated),
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            ended_at=datetime.now(timezone.utc).isoformat(),
        )

        emit_json_stdout(
            {
                "run_id": str(run_id),
                "item_inserted": staging_counts.item_inserted,
                "item_updated": staging_counts.item_updated,
                "gate_inserted": staging_counts.gate_inserted,
                "gate_updated": staging_counts.gate_updated,
            }
        )
        return 0
    except (Exception, SystemExit) as e:
        log_loki_event(
            _PIPELINE_LOGGER,
            level=logging.ERROR,
            event="t7_stage_ingest_failed",
            source=src,
            stage="stage",
            env=get_crawler_env(),
            run_id=str(run_id),
            app_git_sha=app_git_sha,
            input=str(args.input),
            input_name=input_name,
            item_total=item_total,
            gate_total=gate_total,
            error=str(e),
            exc_type=type(e).__name__,
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            ended_at=datetime.now(timezone.utc).isoformat(),
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
