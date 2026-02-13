# backend/services/crawler/official_reconcile_gate/engine.py
from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any

from .diff import build_diff_entries
from .extract import ExtractError
from .fetch import FetchError, OfficialFetcher
from .patch import apply_patch_ops, build_patch_plan
from .policy import PatchPolicy, default_patch_policy
from .registry import ReconcileRegistry, build_default_registry
from .types import AuditLog, OfficialDocument, ReconcileResult, ReconcileRow, RetailRecord


class OfficialReconcileEngine:
    def __init__(
        self,
        *,
        timeout_seconds: float = 5.0,
        user_agent: str | None = None,
        max_redirects: int = 5,
        registry: ReconcileRegistry | None = None,
        policy: PatchPolicy | None = None,
    ) -> None:
        self._registry = registry or build_default_registry()
        self._policy = policy or default_patch_policy()
        self._fetcher = OfficialFetcher(
            timeout_seconds=timeout_seconds,
            user_agent=user_agent,
            max_redirects=max_redirects,
        )

    def close(self) -> None:
        self._fetcher.close()

    def __enter__(self) -> "OfficialReconcileEngine":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def reconcile_one(self, record: RetailRecord, *, raw_record: dict[str, Any] | None = None) -> ReconcileResult:
        canonical_input = _clone_record(record, raw_record=raw_record)
        before_summary = _before_summary(record)
        key = record.url or record.sku_hint

        matcher = self._registry.get_matcher(record.category)
        match_result = matcher.match(record)
        if match_result.status == "skipped" or not match_result.official_url:
            row = ReconcileRow(
                key=key,
                status="skipped",
                official_url=None,
                diff_count=0,
                patch_count=0,
                error=None,
            )
            audit = AuditLog(
                timestamp=_ts_now(),
                source=record.source,
                category=record.category,
                status=row.status,
                official_url=None,
                before_summary=before_summary,
                after_summary=dict(before_summary),
                error=None,
            )
            return ReconcileResult(
                canonical_record=canonical_input,
                row=row,
                audit=audit,
                official_document=None,
                diffs=[],
                patch_plan=[],
            )

        official_url = match_result.official_url
        adapter = self._registry.get_adapter(record.source)

        try:
            official_doc = adapter.fetch_document(official_url, fetcher=self._fetcher)
        except FetchError as e:
            err = _error_text(e)
            row = ReconcileRow(
                key=key,
                status="fetch_failed",
                official_url=official_url,
                diff_count=0,
                patch_count=0,
                error=err,
            )
            audit = AuditLog(
                timestamp=_ts_now(),
                source=record.source,
                category=record.category,
                status=row.status,
                official_url=official_url,
                before_summary=before_summary,
                after_summary={"official_url": official_url},
                error=err,
            )
            return ReconcileResult(
                canonical_record=canonical_input,
                row=row,
                audit=audit,
                official_document=None,
                diffs=[],
                patch_plan=[],
            )
        except ExtractError as e:
            err = _error_text(e)
            row = ReconcileRow(
                key=key,
                status="extract_failed",
                official_url=official_url,
                diff_count=0,
                patch_count=0,
                error=err,
            )
            audit = AuditLog(
                timestamp=_ts_now(),
                source=record.source,
                category=record.category,
                status=row.status,
                official_url=official_url,
                before_summary=before_summary,
                after_summary={"official_url": official_url},
                error=err,
            )
            return ReconcileResult(
                canonical_record=canonical_input,
                row=row,
                audit=audit,
                official_document=None,
                diffs=[],
                patch_plan=[],
            )
        except Exception as e:  # pragma: no cover - defensive
            err = _error_text(e)
            row = ReconcileRow(
                key=key,
                status="extract_failed",
                official_url=official_url,
                diff_count=0,
                patch_count=0,
                error=err,
            )
            audit = AuditLog(
                timestamp=_ts_now(),
                source=record.source,
                category=record.category,
                status=row.status,
                official_url=official_url,
                before_summary=before_summary,
                after_summary={"official_url": official_url},
                error=err,
            )
            return ReconcileResult(
                canonical_record=canonical_input,
                row=row,
                audit=audit,
                official_document=None,
                diffs=[],
                patch_plan=[],
            )

        diffs = _build_generic_diffs(record, official_url=official_url, official_doc=official_doc)
        patch_plan = build_patch_plan(diffs, category=record.category, policy=self._policy)
        canonical_record = apply_patch_ops(canonical_input, patch_plan)

        row = ReconcileRow(
            key=key,
            status="done",
            official_url=official_url,
            diff_count=len(diffs),
            patch_count=len(patch_plan),
            error=None,
        )
        audit = AuditLog(
            timestamp=_ts_now(),
            source=record.source,
            category=record.category,
            status=row.status,
            official_url=official_url,
            before_summary=before_summary,
            after_summary=_after_summary(canonical_record, official_doc),
            error=None,
        )
        return ReconcileResult(
            canonical_record=canonical_record,
            row=row,
            audit=audit,
            official_document=official_doc,
            diffs=diffs,
            patch_plan=patch_plan,
        )


def _clone_record(record: RetailRecord, *, raw_record: dict[str, Any] | None) -> dict[str, Any]:
    if raw_record is not None:
        return copy.deepcopy(raw_record)

    return {
        "source": record.source,
        "category": record.category,
        "title": record.title,
        "url": record.url,
        "sku_hint": record.sku_hint,
        "extra": copy.deepcopy(record.extra),
    }


def _before_summary(record: RetailRecord) -> dict[str, Any]:
    return {
        "title": record.title,
        "url": record.url,
        "sku_hint": record.sku_hint,
    }


def _after_summary(canonical_record: dict[str, Any], official_doc: OfficialDocument) -> dict[str, Any]:
    return {
        "title": canonical_record.get("title"),
        "url": canonical_record.get("url"),
        "official_title": official_doc.title,
        "official_final_url": official_doc.final_url,
    }


def _build_generic_diffs(record: RetailRecord, *, official_url: str, official_doc: OfficialDocument):
    retail_view = {
        "title": record.title,
        "official_url": official_url,
    }
    official_view = {
        "title": official_doc.title,
        "official_url": official_doc.final_url or official_doc.url,
        "content_type": official_doc.content_type,
    }
    return build_diff_entries(retail_view, official_view)


def _ts_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _error_text(exc: Exception, *, max_len: int = 240) -> str:
    raw = " ".join(str(exc).strip().split())
    if len(raw) > max_len:
        return raw[: max_len - 3] + "..."
    return raw
