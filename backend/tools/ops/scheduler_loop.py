"""Stable public CLI surface for the crawler scheduler command."""
from backend.tools.ops.crawler.t10_scheduler_loop import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
