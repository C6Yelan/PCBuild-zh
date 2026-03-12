"""Compatibility wrapper for the stable crawler incremental CLI module path."""
from backend.tools.ops.crawler.t10_run_incremental import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
