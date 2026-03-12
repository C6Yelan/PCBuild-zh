"""Compatibility wrapper for the stable crawler publication CLI module path."""
from backend.tools.ops.crawler.t9_publish_publication import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
