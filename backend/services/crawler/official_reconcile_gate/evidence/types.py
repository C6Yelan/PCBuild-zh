from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

FetchStatus = Literal["fetched", "skipped_robots", "http_error", "unreachable", "too_large", "invalid_url"]


@dataclass(frozen=True)
class BlockSignature:
    name: str
    keywords: tuple[str, ...]


@dataclass(frozen=True)
class FetchResult:
    fetch_status: FetchStatus
    http_status_code: int | None
    final_url: str | None
    content_type: str | None
    content_length: str | None
    content_range: str | None
    server: str | None
    cache_control: str | None
    body_sha256: str | None
    body_snippet: str
    block_reason: str | None
    bytes_read: int
    error: str | None = None


@dataclass(frozen=True)
class EvidenceRecord:
    candidate_url: str
    brand_key: str | None
    retail_url: str | None
    discovery_source: str | None
    robots_allowed: bool
    robots_reason: str | None
    fetch_status: FetchStatus
    http_status_code: int | None
    final_url: str | None
    content_type: str | None
    content_length: str | None
    content_range: str | None
    server: str | None
    cache_control: str | None
    body_sha256: str | None
    body_snippet: str
    block_reason: str | None
