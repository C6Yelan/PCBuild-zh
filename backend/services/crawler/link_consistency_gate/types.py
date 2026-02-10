# backend/services/crawler/link_consistency_gate/types.py
# Link Consistency Gate 的「型別與資料結構定義中心」
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional


@dataclass(frozen=True)
class ListingInput: # Link Gate 的「單筆檢查輸入」
    source: str
    category: str
    title: str
    url: str
    # Allow empty string, but never None.
    sku_hint: str
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None: # 確保 sku_hint 和 extra 不會是 None
        if self.sku_hint is None:  # type: ignore[truthy-bool]
            raise ValueError("sku_hint must not be None")
        if self.extra is None:  # type: ignore[truthy-bool]
            raise ValueError("extra must not be None")


@dataclass(frozen=True)
class PageSignals: # 從 HTML 萃取出的「頁面訊號」
    final_url: str
    http_status: int
    page_title: Optional[str]
    page_h1: Optional[str]
    canonical_url: Optional[str]
    text_hint: Optional[str]


MatchStatus = Literal["match", "mismatch", "uncertain"]


@dataclass(frozen=True)
class MatchDecision: # Link Gate 的「檢查結果」
    status: MatchStatus
    score: Optional[float]
    reason_code: str
    evidence: dict[str, Any]


ReportStatus = Literal["match", "mismatch", "uncertain", "error"]


@dataclass(frozen=True)
class LinkCheckReport: # Link Gate 的「檢查報告」
    source: str
    category: str
    title: str
    url: str
    final_url: str
    status: ReportStatus
    http_status: Optional[int]
    elapsed_ms: int
    reason_code: str
    evidence: dict[str, Any]
    error: Optional[dict[str, Any]] = None


# 以下是 EngineConfig 相關的型別定義，讓 Link Gate 的「檢查引擎」可以有清晰的設定結構
@dataclass(frozen=True)
class FetchConfig:
    timeout_s: float
    max_redirects: int
    max_bytes: int


@dataclass(frozen=True)
class PacingConfig:
    min_interval_ms: int
    jitter_ms: int
    max_concurrency_per_host: int = 1


@dataclass(frozen=True)
class BlockDetectionConfig:
    enabled: bool
    patterns: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EngineConfig:
    fetch: FetchConfig
    pacing: PacingConfig
    block: BlockDetectionConfig
