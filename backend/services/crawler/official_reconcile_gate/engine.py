# backend/services/crawler/official_reconcile_gate/engine.py
"""Minimal orchestration skeleton for T6 official reconciliation."""

from __future__ import annotations

from .registry import get_category_matcher, get_source_adapter
from .types import (
    DecisionAction,
    ListingInput,
    MatchDecisionWithOfficial,
    MatchStatus,
    T6Result,
)

MAX_CANDIDATES = 5


def _make_match( # 把 status/confidence/reason_code/evidence 組成一個標準 match 決策 dict。
    status: MatchStatus,
    confidence: float,
    reason_code: str,
    evidence: dict[str, object] | None = None,
) -> MatchDecisionWithOfficial:
    return {
        "status": status,
        "confidence": confidence,
        "reason_code": reason_code,
        "evidence": evidence or {},
    }


def _make_result( # 把最終結果包成 T6Result 的格式，包含 match 決策、diff_items、decision_action、decision_reason、patch、audit 和 error。
    match: MatchDecisionWithOfficial,
    decision_action: DecisionAction,
    decision_reason: str,
    error: dict[str, object] | None,
) -> T6Result:
    return {
        "match": match,
        "diff_items": [],
        "decision_action": decision_action,
        "decision_reason": decision_reason,
        "patch": None,
        "audit": [],
        "error": error,
    }


def _best_decision( # 從所有候選決策中挑「最佳」的決策。優先選擇 matched 的決策，如果沒有 matched 的，就選 confidence 最高的。
    decisions: list[MatchDecisionWithOfficial],
) -> MatchDecisionWithOfficial:
    matched = [d for d in decisions if d["status"] == "matched"]
    pool = matched if matched else decisions
    return max(pool, key=lambda d: d["confidence"])


def reconcile_one(item: ListingInput, official_sources: list[str]) -> T6Result:
    try:
        matcher = get_category_matcher(item["category"])
        if matcher is None:
            return _make_result(
                match=_make_match(
                    status="unmatched",
                    confidence=0.0,
                    reason_code="NO_MATCHER",
                ),
                decision_action="skip",
                decision_reason="no category matcher registered",
                error={
                    "type": "NoMatcher",
                    "message": f"no matcher registered for category: {item['category']}",
                },
            )

        adapters = []
        for source in official_sources:
            adapter = get_source_adapter(source)
            if adapter is not None:
                adapters.append(adapter)

        if not adapters:
            return _make_result(
                match=_make_match(
                    status="unmatched",
                    confidence=0.0,
                    reason_code="NO_ADAPTER",
                ),
                decision_action="skip",
                decision_reason="no source adapter registered",
                error={
                    "type": "NoAdapter",
                    "message": "no source adapter registered for provided official_sources",
                },
            )

        decisions: list[MatchDecisionWithOfficial] = []
        errors: list[dict[str, object]] = []

        for adapter in adapters:
            try:
                candidates = adapter.search_candidates(item)
            except Exception as exc:
                errors.append(
                    {
                        "type": "AdapterSearchError",
                        "message": f"{adapter.official_source}: {exc}",
                    }
                )
                continue

            for candidate in candidates[:MAX_CANDIDATES]:
                try:
                    signals = adapter.fetch_signals(candidate)
                    score = matcher.score(item, candidate, signals)
                    decision = matcher.decide(item, candidate, signals, score)
                    decisions.append(decision)
                except Exception as exc:
                    errors.append(
                        {
                            "type": "CandidateProcessError",
                            "message": f"{adapter.official_source}: {exc}",
                            "candidate_url": candidate.get("candidate_url", ""),
                        }
                    )

        if not decisions:
            error_payload: dict[str, object] | None = None
            decision_action: DecisionAction = "keep_retail"
            decision_reason = "no candidate decision produced"
            reason_code = "NO_DECISION"

            if errors:
                error_payload = {
                    "type": "ProcessingError",
                    "message": "exceptions occurred during reconciliation",
                    "details": errors,
                }
                decision_action = "skip"
                decision_reason = "exceptions occurred during reconciliation"
                reason_code = "PROCESSING_ERROR"

            return _make_result(
                match=_make_match(
                    status="unmatched",
                    confidence=0.0,
                    reason_code=reason_code,
                ),
                decision_action=decision_action,
                decision_reason=decision_reason,
                error=error_payload,
            )

        best = _best_decision(decisions)
        status = best["status"]
        action: DecisionAction = "quarantine" if status == "ambiguous" else "keep_retail"

        partial_error: dict[str, object] | None = None
        if errors:
            partial_error = {
                "type": "PartialFailure",
                "message": "some candidates failed during reconciliation",
                "details": errors,
            }

        return _make_result(
            match=best,
            decision_action=action,
            decision_reason=best["reason_code"],
            error=partial_error,
        )
    except Exception as exc:
        return _make_result(
            match=_make_match(
                status="unmatched",
                confidence=0.0,
                reason_code="INTERNAL_ERROR",
            ),
            decision_action="skip",
            decision_reason="internal error during reconciliation",
            error={
                "type": "ReconcileOneError",
                "message": str(exc),
            },
        )


def reconcile_many(
    items: list[ListingInput],
    official_sources: list[str],
) -> tuple[list[T6Result], dict[str, int]]:
    counters: dict[str, int] = {
        "matched": 0,
        "unmatched": 0,
        "ambiguous": 0,
        "error": 0,
        "skip": 0,
        "quarantine": 0,
    }
    results: list[T6Result] = []

    for item in items:
        try:
            result = reconcile_one(item, official_sources)
        except Exception as exc:
            result = _make_result(
                match=_make_match(
                    status="unmatched",
                    confidence=0.0,
                    reason_code="INTERNAL_ERROR",
                ),
                decision_action="skip",
                decision_reason="internal error during batch reconciliation",
                error={"type": "ReconcileManyError", "message": str(exc)},
            )

        results.append(result)

        status = result["match"]["status"]
        if status in counters:
            counters[status] += 1

        if result["error"] is not None:
            counters["error"] += 1
        if result["decision_action"] == "skip":
            counters["skip"] += 1
        if result["decision_action"] == "quarantine":
            counters["quarantine"] += 1

    return results, counters
