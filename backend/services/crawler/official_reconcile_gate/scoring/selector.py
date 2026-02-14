from __future__ import annotations

from typing import Any

from .types import DecisionRecord, ScoreBreakdown


def rank_candidates(per_retail_item_candidates: list[ScoreBreakdown]) -> list[ScoreBreakdown]:
    return sorted(
        per_retail_item_candidates,
        key=lambda row: (-row.total_score, row.official_url.lower(), row.official_url),
    )


def select_best(
    per_retail_item_candidates: list[ScoreBreakdown],
    *,
    plan: dict[str, Any] | None = None,
    topk: int = 5,
    min_accept_score: int = 3,
) -> DecisionRecord:
    safe_plan = plan if isinstance(plan, dict) else {}
    ranked = rank_candidates(per_retail_item_candidates)
    summary_limit = max(0, int(topk))

    plan_index = _to_int(safe_plan.get("plan_index"), default=-1)
    retail_url = _to_text(safe_plan.get("retail_url") or safe_plan.get("url"))
    source = _to_text(safe_plan.get("source"))
    category = _to_text(safe_plan.get("category"))
    brand_key = _to_optional_text(safe_plan.get("brand_key"))

    if not ranked:
        return DecisionRecord(
            plan_index=plan_index,
            retail_url=retail_url,
            source=source,
            category=category,
            brand_key=brand_key,
            decision="no_candidates",
            decision_reason="no robots_allowed candidates",
            chosen_official_url=None,
            confidence=0,
            top1_score=None,
            top_k_summary=[],
        )

    top1 = ranked[0]
    top1_score = top1.total_score
    if top1_score < min_accept_score:
        decision = "needs_manual_review"
        decision_reason = f"top1_score {top1_score} < min_accept_score {min_accept_score}"
    else:
        decision = "accepted"
        decision_reason = f"top1_score {top1_score} >= min_accept_score {min_accept_score}"

    return DecisionRecord(
        plan_index=plan_index if plan_index >= 0 else top1.plan_index,
        retail_url=retail_url or top1.retail_url,
        source=source or top1.source,
        category=category or top1.category,
        brand_key=brand_key if brand_key is not None else top1.brand_key,
        decision=decision,
        decision_reason=decision_reason,
        chosen_official_url=top1.official_url,
        confidence=_score_to_confidence(top1_score),
        top1_score=top1_score,
        top_k_summary=[
            {
                "official_url": item.official_url,
                "score": item.total_score,
                "reasons": list(item.reasons),
                "components": dict(item.components),
            }
            for item in ranked[:summary_limit]
        ],
    )


def _score_to_confidence(score: int) -> int:
    if score <= 0:
        return 0
    return min(100, score * 20)


def _to_text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    return ""


def _to_optional_text(value: Any) -> str | None:
    text = _to_text(value)
    return text if text else None


def _to_int(value: Any, *, default: int) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default
