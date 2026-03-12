"""Compatibility wrapper for the stable crawler publication listing CLI module path."""
from backend.tools.ops.crawler.t9_list_publications import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
