# backend/tools/ops/crawler/incremental/run_incremental_cli.py
from __future__ import annotations

import argparse
import logging
from typing import Any

from backend.core.obs_events import ensure_cli_logging, log_loki_event
from backend.services.crawler.staging.conventions import get_crawler_env
from .incremental_cli import incremental_cli_options_from_namespace
from .incremental_run_flow import (
    apply_incremental_no_change_phase,
    build_incremental_run_context,
    finalize_incremental_run,
    log_incremental_start,
    record_incremental_unhandled_error,
    resolve_incremental_targets,
    run_incremental_changed_phases,
    run_incremental_fetch_phase,
)

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


def _build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Run incremental refresh (fetch -> parse/gates -> stage -> merge -> publish)"
    )
    ap.add_argument("--source", required=True, help="crawler source id, e.g. coolpc")
    ap.add_argument("--parts", default="all", help="comma-separated part list, default: all")
    ap.add_argument("--dry-run", action="store_true", help="do not write DB and do not publish")

    pub_group = ap.add_mutually_exclusive_group()
    pub_group.add_argument("--publish", dest="publish", action="store_true", help="publish to pointer after merge")
    pub_group.add_argument("--no-publish", dest="publish", action="store_false", help="skip publish (default)")
    ap.set_defaults(publish=False)

    ap.add_argument("--max-items", type=int, default=0, help="per-part protection cap; <=0 means unlimited")
    ap.add_argument(
        "--t5-limit",
        type=int,
        default=0,
        help="link consistency check first N rows; <=0 means full",
    )
    ap.add_argument("--t5-min-interval-ms", type=int, default=1500)
    ap.add_argument("--t5-timeout-s", type=float, default=10.0)
    ap.add_argument("--t5-max-redirects", type=int, default=5)
    ap.add_argument("--t5-max-bytes", type=int, default=4194304)
    ap.add_argument("--t5-block-pattern", action="append", default=[])
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
        env=get_crawler_env(),
        run_id=run_id,
        **extra,
    )


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    options = incremental_cli_options_from_namespace(args)
    if int(options.max_items) < 0:
        raise SystemExit("--max-items must be >= 0")

    # Keep this module path stable for existing SOP/CLI usage; detailed steps live in sibling helpers.
    ensure_cli_logging(logger=_PIPELINE_LOGGER)
    context = build_incremental_run_context(args=args, options=options)
    rc = 0

    try:
        targets, resolve_rc = resolve_incremental_targets(context)
        if resolve_rc != 0:
            rc = 2

        log_incremental_start(
            context,
            log_event=_log_event,
        )

        changed_parts, fetch_rc = run_incremental_fetch_phase(
            context,
            targets=targets,
            log_event=_log_event,
        )
        if fetch_rc != 0:
            rc = 2

        if changed_parts:
            rc = run_incremental_changed_phases(
                context,
                changed_parts=changed_parts,
                current_rc=rc,
                log_event=_log_event,
            )
        else:
            rc = apply_incremental_no_change_phase(
                context,
                current_rc=rc,
                log_event=_log_event,
            )
    except Exception as exc:
        record_incremental_unhandled_error(context, exc)
        rc = 2

    return finalize_incremental_run(context, rc=rc)


if __name__ == "__main__":
    raise SystemExit(main())
