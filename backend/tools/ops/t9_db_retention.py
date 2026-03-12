"""Compatibility wrapper for the stable maintenance retention CLI module path."""
from backend.tools.ops.maintenance.t9_db_retention import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
