# backend/services/chat/service/retrieval.py
"""Retrieval and context-pack coordination helpers for chat orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from backend.services.chat.build_policy import BuildRequestProfile, apply_build_candidate_gate
from backend.services.chat.context_pack import P1Demand


@dataclass(slots=True)
class RetrievalArtifacts:
    compressed_candidates: dict[str, list[dict[str, object]]]
    drop_log: dict[str, dict[str, object]]
    context_pack_text: str | None
    context_pack_hash: str
    context_pack_meta: dict[str, object]

    @classmethod
    def empty(cls) -> RetrievalArtifacts:
        return cls(
            compressed_candidates={},
            drop_log={},
            context_pack_text=None,
            context_pack_hash="-",
            context_pack_meta={},
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


def _retrieval_category_counts(retrieval_result: Any) -> str:
    items_by_category = getattr(retrieval_result, "items_by_category", {})
    if not isinstance(items_by_category, dict):
        return ""
    return ",".join(
        f"{category}:{len(items_by_category.get(category, []))}"
        for category in sorted(items_by_category.keys())
    )


def prepare_retrieval_artifacts(
    *,
    db: Any,
    settings: Any,
    categories: list[str],
    top_k: int,
    retrieval_demand: P1Demand | None,
    build_profile: BuildRequestProfile,
    normalized_demand: object,
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
        category_counts_before = _retrieval_category_counts(retrieval_result)
        build_gate_result = apply_build_candidate_gate(
            retrieval_result,
            profile=build_profile,
        )
        retrieval_result = build_gate_result.retrieval_result
        if build_gate_result.events:
            warnings.extend(
                f"build_gate:{event['stage']}:{event['category']}:{event['reason']}:{event['action']}"
                for event in build_gate_result.events
            )
            log_operation(
                "build_candidate_gate",
                enabled=build_profile.enabled,
                target_total_price=build_profile.target_total_price,
                minimum_budget_utilization=build_profile.minimum_budget_utilization,
                category_counts_before=category_counts_before,
                category_counts_after=_retrieval_category_counts(retrieval_result),
                gate_events=build_gate_result.events,
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
            demand=normalized_demand,
        )
        context_pack_text = context_pack.text
        context_pack_hash = context_pack.hash
        context_pack_meta = dict(getattr(context_pack, "meta", None) or {})
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
            context_pack_meta=context_pack_meta,
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
