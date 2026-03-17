# backend/tools/ops/crawler/publish_publication_cli.py
"""Compatibility wrapper for the crawler publication CLI module path."""

from .publication.publish_publication_cli import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
