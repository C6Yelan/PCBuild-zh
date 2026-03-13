"""Compatibility wrapper for the crawler publication list CLI module path."""

from .publication.list_publications_cli import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
