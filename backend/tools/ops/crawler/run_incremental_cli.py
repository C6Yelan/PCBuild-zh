"""Compatibility wrapper for the crawler incremental run CLI module path."""

from .incremental.run_incremental_cli import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
