# backend/services/chat/service/retrieval.py
"""Retrieval and context-pack coordination helpers for chat orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from backend.services.chat.context_pack import P1Demand


@dataclass(slots=True)
class RetrievalArtifacts:
    compressed_candidates: dict[str, list[dict[str, object]]]
    drop_log: dict[str, dict[str, object]]
    context_pack_text: str | None
    context_pack_hash: str

    @classmethod
    def empty(cls) -> RetrievalArtifacts:
        return cls(
            compressed_candidates={},
            drop_log={},
            context_pack_text=None,
            context_pack_hash="-",
        )


def empty_retrieval_artifacts() -> RetrievalArtifacts:
    return RetrievalArtifacts.empty()


def _fallback_count(drop_entries: list[dict[str, object]]) -> int:
    return sum(
        1
        for entry in drop_entries
        if isinstance(entry.get("reason"), list) and "fallback_used" in entry["reason"]
    )


def _dropped_specs_count(drop_entries: list[dict[str, object]]) -> int:
    return sum(
        len(entry["dropped_specs"])
        for entry in drop_entries
        if isinstance(entry.get("dropped_specs"), list)
    )


def _truncated_specs_count(drop_entries: list[dict[str, object]]) -> int:
    return sum(
        len(entry["truncated_specs"])
        for entry in drop_entries
        if isinstance(entry.get("truncated_specs"), dict)
    )


def _category_counts(
    compressed_candidates: dict[str, list[dict[str, object]]],
) -> str:
    return ",".join(
        f"{category}:{len(compressed_candidates.get(category, []))}"
        for category in sorted(compressed_candidates.keys())
    )


def prepare_retrieval_artifacts(
    *,
    db: Any,
    settings: Any,
    categories: list[str],
    top_k: int,
    retrieval_demand: P1Demand | None,
    env: str,
    warnings: list[str],
    retrieve_topk_candidates: Callable[..., Any],
    compress_candidates: Callable[..., tuple[dict[str, list[dict[str, object]]], dict[str, dict[str, object]]]],
    build_context_pack: Callable[..., Any],
    log_operation: Callable[..., Any],
) -> RetrievalArtifacts:
    try:
        retrieval_result = retrieve_topk_candidates(
            db,
            categories=categories,
            top_k=top_k,
            demand=retrieval_demand,
            env=env,
        )
        compressed_candidates, drop_log = compress_candidates(
            retrieval_result,
            spec_whitelist_by_category=settings.p2_spec_whitelist_by_category,
            max_value_len=settings.p2_max_value_len,
            max_specs_per_part=settings.p2_max_specs_per_part,
        )
        drop_entries = [
            entry for entry in drop_log.values() if isinstance(entry, dict)
        ]
        log_operation(
            "p2_compress",
            env=env,
            top_k=top_k,
            requested_categories=",".join(categories),
            returned_categories=",".join(sorted(compressed_candidates.keys())),
            returned_count=sum(len(items) for items in compressed_candidates.values()),
            drop_log_count=len(drop_entries),
            fallback_count=_fallback_count(drop_entries),
            dropped_specs_count=_dropped_specs_count(drop_entries),
            truncated_specs_count=_truncated_specs_count(drop_entries),
            max_value_len=settings.p2_max_value_len,
            max_specs_per_part=settings.p2_max_specs_per_part,
        )

        context_pack = build_context_pack(
            compressed_by_category=compressed_candidates,
            category_order=categories,
            enable_rerank=True,
            demand=retrieval_demand,
        )
        context_pack_text = context_pack.text
        context_pack_hash = context_pack.hash
        log_operation(
            "p3_context_pack",
            env=env,
            context_pack_hash=context_pack_hash,
            context_pack_chars=len(context_pack.text),
            category_counts=_category_counts(compressed_candidates),
        )
        return RetrievalArtifacts(
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
            context_pack_text=context_pack_text,
            context_pack_hash=context_pack_hash,
        )
    except Exception as exc:
        warnings.append("p1_retrieval_failed")
        log_operation(
            "p1_retrieval_failed",
            error_type=type(exc).__name__,
            env=env,
            categories=",".join(categories),
            top_k=top_k,
        )
        return empty_retrieval_artifacts()


__all__ = [
    "RetrievalArtifacts",
    "empty_retrieval_artifacts",
    "prepare_retrieval_artifacts",
]
