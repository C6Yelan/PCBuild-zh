"""Stable public CLI entrypoint for DQ check against a directory of JSON files."""

from backend.tools.crawler.dq.cli_dir import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
