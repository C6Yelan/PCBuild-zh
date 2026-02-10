# backend/services/crawler/__init__.py
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .config import CrawlerSettings
    from .http_client import CrawlerHttpClient, FetchResult

__all__ = ["CrawlerSettings", "CrawlerHttpClient", "FetchResult"]


def __getattr__(name: str) -> Any:
    # Lazy imports keep lightweight tools (e.g. link_consistency_check_json) runnable
    # without pulling optional runtime dependencies at package import time.
    if name == "CrawlerSettings":
        from .config import CrawlerSettings as _CrawlerSettings

        return _CrawlerSettings
    if name in ("CrawlerHttpClient", "FetchResult"):
        from .http_client import CrawlerHttpClient as _CrawlerHttpClient
        from .http_client import FetchResult as _FetchResult

        return {"CrawlerHttpClient": _CrawlerHttpClient, "FetchResult": _FetchResult}[name]
    raise AttributeError(name)
