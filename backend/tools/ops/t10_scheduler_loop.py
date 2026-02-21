# backend/tools/ops/t10_scheduler_loop.py
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

import sqlalchemy as sa

from backend.core.obs_events import ensure_cli_logging, log_loki_event
from backend.db import engine
from backend.tools.ops.t10_run_incremental import main as run_incremental_main

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


def _get_env() -> str:
    return os.getenv("APP_ENV") or os.getenv("ENV") or "prod"


def _build_lock_key(source: str, parts: str) -> int:
    seed = f"pcbuild:t10:{source}:{parts}".encode("utf-8")
    digest = hashlib.sha256(seed).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


def _log_scheduler(event: str, *, source: str, **fields: Any) -> None:
    log_loki_event(
        _PIPELINE_LOGGER,
        event=event,
        source=source,
        stage="scheduler",
        env=_get_env(),
        **fields,
    )


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="T10 scheduler loop: run incremental refresh periodically")
    ap.add_argument("--source", required=True)
    ap.add_argument("--parts", default="all")
    ap.add_argument("--interval-seconds", type=int, default=900, help="loop interval in seconds (default: 900)")
    ap.add_argument("--dry-run", action="store_true")

    pub_group = ap.add_mutually_exclusive_group()
    pub_group.add_argument("--publish", dest="publish", action="store_true")
    pub_group.add_argument("--no-publish", dest="publish", action="store_false")
    ap.set_defaults(publish=False)

    ap.add_argument("--max-items", type=int, default=0)
    ap.add_argument(
        "--lock-key",
        type=int,
        default=None,
        help="optional postgres advisory lock key override; default derives from source+parts",
    )
    return ap


def _run_once_with_lock(*, source: str, parts: str, lock_key: int, runner_argv: list[str]) -> tuple[bool, int | None]:
    with engine.connect() as conn:
        acquired = bool(conn.execute(sa.text("SELECT pg_try_advisory_lock(:k)"), {"k": lock_key}).scalar_one())
        if not acquired:
            return False, None

        try:
            rc = int(run_incremental_main(runner_argv))
            return True, rc
        finally:
            conn.execute(sa.text("SELECT pg_advisory_unlock(:k)"), {"k": lock_key})


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if int(args.interval_seconds) <= 0:
        raise SystemExit("--interval-seconds must be > 0")
    if int(args.max_items) < 0:
        raise SystemExit("--max-items must be >= 0")

    source = str(args.source).strip().lower()
    parts = str(args.parts).strip() or "all"
    interval_s = int(args.interval_seconds)
    lock_key = int(args.lock_key) if args.lock_key is not None else _build_lock_key(source, parts)

    runner_argv = ["--source", source, "--parts", parts, "--max-items", str(int(args.max_items))]
    if bool(args.dry_run):
        runner_argv.append("--dry-run")
    if bool(args.publish):
        runner_argv.append("--publish")
    else:
        runner_argv.append("--no-publish")

    ensure_cli_logging(logger=_PIPELINE_LOGGER)
    _log_scheduler(
        "t10_scheduler_start",
        source=source,
        parts=parts,
        interval_seconds=interval_s,
        dry_run=bool(args.dry_run),
        publish=bool(args.publish),
        max_items=int(args.max_items),
        lock_key=lock_key,
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    try:
        while True:
            tick_t0 = time.monotonic()
            tick_started = datetime.now(timezone.utc).isoformat()

            try:
                acquired, run_rc = _run_once_with_lock(
                    source=source,
                    parts=parts,
                    lock_key=lock_key,
                    runner_argv=runner_argv,
                )
            except Exception as e:
                _log_scheduler(
                    "t10_scheduler_tick_failed",
                    source=source,
                    parts=parts,
                    lock_key=lock_key,
                    started_at=tick_started,
                    error=str(e),
                    exc_type=type(e).__name__,
                )
                acquired = False
                run_rc = None

            elapsed_ms = int((time.monotonic() - tick_t0) * 1000)
            if acquired:
                _log_scheduler(
                    "t10_scheduler_tick_done",
                    source=source,
                    parts=parts,
                    lock_key=lock_key,
                    started_at=tick_started,
                    elapsed_ms=elapsed_ms,
                    run_rc=int(run_rc or 0),
                )
            else:
                _log_scheduler(
                    "t10_scheduler_tick_skipped_locked",
                    source=source,
                    parts=parts,
                    lock_key=lock_key,
                    started_at=tick_started,
                    elapsed_ms=elapsed_ms,
                )

            sleep_s = max(0, interval_s - int((time.monotonic() - tick_t0)))
            time.sleep(sleep_s)
    except KeyboardInterrupt:
        _log_scheduler(
            "t10_scheduler_stop",
            source=source,
            parts=parts,
            lock_key=lock_key,
            stopped_at=datetime.now(timezone.utc).isoformat(),
        )
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
