# backend/tools/ops/crawler/scheduler_loop_cli.py
"""Compatibility wrapper for the crawler scheduler CLI module path."""

from .incremental.scheduler_loop_cli import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
