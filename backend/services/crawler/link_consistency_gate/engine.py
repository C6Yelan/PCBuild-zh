from __future__ import annotations

import httpx

from .engine_runtime import check_listing
from .engine_support import (
    compile_block_patterns,
    coolpc_try_decode_ibuy,
    extract_raw_query_param,
    one_line,
)
from .fetch import Fetcher
from .types import EngineConfig, LinkCheckReport, ListingInput


class LinkCheckEngine:
    def __init__(self, config: EngineConfig) -> None:
        self._config = config
        self._client = httpx.Client(
            follow_redirects=False,
            timeout=httpx.Timeout(config.fetch.timeout_s),
        )
        self._fetcher = Fetcher(self._client, fetch=config.fetch, pacing=config.pacing)
        self._block_regexes = _compile_block_patterns(config.block)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "LinkCheckEngine":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def check_one(self, listing: ListingInput) -> LinkCheckReport:
        return check_listing(self, listing)

    def _decode_listing_url(self, url: str) -> str | None:
        return _coolpc_try_decode_ibuy(url)

    def _one_line_error(self, exc: Exception) -> str:
        return _one_line(str(exc), max_len=240)


def _compile_block_patterns(cfg):
    return compile_block_patterns(cfg)


def _one_line(text: str, *, max_len: int) -> str:
    return one_line(text, max_len=max_len)


def _coolpc_try_decode_ibuy(url: str) -> str | None:
    return coolpc_try_decode_ibuy(url)


def _extract_raw_query_param(query: str, key: str) -> str | None:
    return extract_raw_query_param(query, key)
