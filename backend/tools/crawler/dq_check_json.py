"""Stable public CLI entrypoint for DQ check against a JSON file."""

from backend.tools.crawler.dq.cli_json import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
