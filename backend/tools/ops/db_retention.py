"""Stable public CLI surface for the maintenance retention command."""
from backend.tools.ops.maintenance.db_retention_cli import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
