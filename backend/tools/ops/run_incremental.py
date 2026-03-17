# backend/tools/ops/run_incremental.py
"""Stable public CLI surface for the crawler incremental run command."""
from backend.tools.ops.crawler.run_incremental_cli import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
