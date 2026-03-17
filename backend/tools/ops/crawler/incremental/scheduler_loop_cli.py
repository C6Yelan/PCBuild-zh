# backend/tools/ops/crawler/incremental/scheduler_loop_cli.py
from __future__ import annotations

import argparse
import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import Any

import sqlalchemy as sa

from backend.core.obs_events import ensure_cli_logging, log_loki_event
from backend.db import engine
from backend.services.crawler.staging.conventions import get_crawler_env
from .incremental_cli import (
    build_incremental_argv,
    incremental_cli_options_from_namespace,
)
from .run_incremental_cli import main as run_incremental_main

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


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
        env=get_crawler_env(),
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
    ap.add_argument("--t5-limit", type=int, default=200)
    ap.add_argument("--t5-min-interval-ms", type=int, default=1500)
    ap.add_argument("--t5-timeout-s", type=float, default=10.0)
    ap.add_argument("--t5-max-redirects", type=int, default=5)
    ap.add_argument("--t5-max-bytes", type=int, default=4194304)
    ap.add_argument("--t5-block-pattern", action="append", default=[])
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
    options = incremental_cli_options_from_namespace(args)
    if int(options.max_items) < 0:
        raise SystemExit("--max-items must be >= 0")

    source = options.source
    parts = options.parts
    interval_s = int(args.interval_seconds)
    lock_key = int(args.lock_key) if args.lock_key is not None else _build_lock_key(source, parts)
    runner_argv = build_incremental_argv(options)

    ensure_cli_logging(logger=_PIPELINE_LOGGER)
    _log_scheduler(
        "t10_scheduler_start",
        source=source,
        parts=parts,
        interval_seconds=interval_s,
        dry_run=options.dry_run,
        publish=options.publish,
        max_items=int(options.max_items),
        t5_limit=int(options.t5_limit),
        t5_min_interval_ms=int(options.t5_min_interval_ms),
        t5_timeout_s=float(options.t5_timeout_s),
        t5_max_redirects=int(options.t5_max_redirects),
        t5_max_bytes=int(options.t5_max_bytes),
        t5_block_pattern_count=int(len(options.t5_block_pattern)),
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
