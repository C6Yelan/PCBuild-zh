# backend/services/crawler/official_reconcile_gate/types.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional


ReconcileStatus = Literal["skipped", "matched", "fetch_failed", "extract_failed", "done"]
DiffSeverity = Literal["info", "warn"]
PatchOpType = Literal["replace", "add", "remove"]


@dataclass(frozen=True)
class RetailRecord:
    source: str
    category: str
    title: str
    url: str
    sku_hint: str
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.sku_hint is None:  # type: ignore[truthy-bool]
            raise ValueError("sku_hint must not be None")
        if self.extra is None:  # type: ignore[truthy-bool]
            raise ValueError("extra must not be None")


@dataclass(frozen=True)
class MatchResult:
    status: Literal["skipped", "matched"]
    official_url: Optional[str]
    reason: str


@dataclass(frozen=True)
class FetchedResponse:
    url: str
    final_url: str
    status_code: int
    fetched_at: str
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class OfficialDocument:
    url: str
    final_url: str
    status_code: int
    fetched_at: str
    content_type: str
    title: Optional[str] = None
    raw_excerpt: Optional[str] = None


@dataclass(frozen=True)
class DiffEntry:
    path: str
    retail_value: Any
    official_value: Any
    retail_missing: bool
    official_missing: bool
    severity: DiffSeverity


@dataclass(frozen=True)
class PatchOp:
    op: PatchOpType
    path: str
    reason: str
    value: Any = None


@dataclass(frozen=True)
class ReconcileRow:
    key: str
    status: ReconcileStatus
    official_url: Optional[str]
    diff_count: int
    patch_count: int
    error: Optional[str] = None


@dataclass(frozen=True)
class AuditLog:
    timestamp: str
    source: str
    category: str
    status: ReconcileStatus
    official_url: Optional[str]
    before_summary: dict[str, Any]
    after_summary: dict[str, Any]
    error: Optional[str] = None


@dataclass(frozen=True)
class ReconcileResult:
    canonical_record: dict[str, Any]
    row: ReconcileRow
    audit: AuditLog
    official_document: Optional[OfficialDocument]
    diffs: list[DiffEntry]
    patch_plan: list[PatchOp]
