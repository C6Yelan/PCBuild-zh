from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Any, Iterator, Optional
from urllib.parse import urlsplit

from backend.services.crawler.official_reconcile_gate.scoring.scorer import score_candidate
from backend.services.crawler.official_reconcile_gate.scoring.selector import rank_candidates, select_best
from backend.services.crawler.official_reconcile_gate.scoring.types import DecisionRecord

_FIELD_MAP = {
    "plan_index": ("plan_index",),
    "plan_retail_url": ("retail_url", "url"),
    "candidate_plan_index": ("plan_index",),
    "candidate_retail_url": ("retail_url",),
    "candidate_url": ("official_url", "candidate_url", "url"),
    "candidate_robots_allowed": ("robots_allowed",),
    "evidence_url": ("candidate_url", "official_url", "url"),
    "evidence_retail_url": ("retail_url",),
    "evidence_block_reason": ("block_reason",),
}


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    if args.topk <= 0 or args.min_accept_score < 0:
        print("error: invalid --topk or --min-accept-score", file=sys.stderr)
        return 2

    try:
        plans = _load_json_array(args.plans)
        candidates = list(_iter_json_rows(args.gated_candidates))
        evidence_rows = list(_iter_json_rows(args.evidence))
        plan_failure_reason_by_plan_index = _load_plan_failure_reason_map(args.plan_failure_map)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    candidates_by_plan, candidates_by_retail = _index_candidates(candidates)
    evidence_by_pair, evidence_by_url = _index_evidence(evidence_rows)

    stats = {
        "total_retail_items": 0,
        "accepted": 0,
        "needs_manual_review": 0,
        "no_candidates": 0,
        "top1_score_sum": 0.0,
        "top1_score_count": 0,
        "blocked_seen_count": {},
        "errors_count": 0,
    }

    ranked_f = None
    try:
        if args.ranked_output:
            ranked_f = open(args.ranked_output, "w", encoding="utf-8")
        with open(args.output, "w", encoding="utf-8") as decision_f:
            for idx, raw_plan in enumerate(plans):
                stats["total_retail_items"] += 1
                plan = _normalize_plan(raw_plan, idx)
                try:
                    decision, ranked = _score_one_plan(
                        plan,
                        idx=idx,
                        topk=args.topk,
                        min_accept_score=args.min_accept_score,
                        candidates_by_plan=candidates_by_plan,
                        candidates_by_retail=candidates_by_retail,
                        evidence_by_pair=evidence_by_pair,
                        evidence_by_url=evidence_by_url,
                        blocked_seen_count=stats["blocked_seen_count"],
                    )
                except Exception:
                    stats["errors_count"] += 1
                    decision = _internal_error_decision(plan, idx=idx)
                    ranked = []
                decision = _apply_plan_failure_reason(
                    decision,
                    idx=idx,
                    reason_by_plan_index=plan_failure_reason_by_plan_index,
                )

                _accumulate_decision_stats(stats, decision)
                decision_f.write(json.dumps(asdict(decision), ensure_ascii=False) + "\n")

                if ranked_f is not None:
                    for rank, breakdown in enumerate(ranked):
                        ranked_row = {
                            "plan_index": decision.plan_index,
                            "retail_url": decision.retail_url,
                            "source": decision.source,
                            "category": decision.category,
                            "brand_key": decision.brand_key,
                            "rank": rank,
                            "official_url": breakdown.official_url,
                            "total_score": breakdown.total_score,
                            "components": breakdown.components,
                            "reasons": breakdown.reasons,
                            "matched_tokens": breakdown.matched_tokens,
                            "title_token_hits": breakdown.title_token_hits,
                            "block_reason": breakdown.block_reason,
                            "content_type": breakdown.content_type,
                        }
                        ranked_f.write(json.dumps(ranked_row, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if ranked_f is not None:
            ranked_f.close()

    _print_stats(stats)
    return 0


def _parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="t6_score_official_candidates")
    p.add_argument("--plans", required=True)
    p.add_argument("--gated-candidates", required=True)
    p.add_argument("--evidence", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--ranked-output")
    p.add_argument("--topk", type=int, default=5)
    p.add_argument("--min-accept-score", type=int, default=3)
    p.add_argument("--plan-failure-map", help="optional JSON map from plan_index to no-candidate reason")
    return p.parse_args(argv)


def _load_json_array(path: str) -> list[Any]:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, list):
        raise ValueError("plans must be a JSON array")
    return payload


def _load_plan_failure_reason_map(path: str | None) -> dict[int, str]:
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise ValueError("plan-failure-map must be a JSON object")
    out: dict[int, str] = {}
    for raw_key, raw_value in payload.items():
        if not isinstance(raw_value, str):
            continue
        text = raw_value.strip()
        if not text:
            continue
        try:
            key = int(str(raw_key))
        except ValueError:
            continue
        out[key] = text
    return out


def _iter_json_rows(path: str) -> Iterator[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        first = _peek_first_non_ws_char(f)
        f.seek(0)
        if first == "[":
            payload = json.load(f)
            if not isinstance(payload, list):
                raise ValueError(f"{path} must be JSON array or JSONL")
            for row in payload:
                if isinstance(row, dict):
                    yield dict(row)
            return

        for lineno, line in enumerate(f, start=1):
            text = line.strip()
            if not text:
                continue
            row = json.loads(text)
            if not isinstance(row, dict):
                raise ValueError(f"{path} line {lineno} must be object")
            yield dict(row)


def _peek_first_non_ws_char(f) -> str:
    while True:
        ch = f.read(1)
        if ch == "":
            return ""
        if not ch.isspace():
            return ch


def _normalize_plan(raw_plan: Any, idx: int) -> dict[str, Any]:
    if isinstance(raw_plan, dict):
        plan = dict(raw_plan)
    else:
        plan = {}
    plan.setdefault("plan_index", idx)
    return plan


def _index_candidates(
    candidates: list[dict[str, Any]],
) -> tuple[dict[int, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    by_plan: dict[int, list[dict[str, Any]]] = {}
    by_retail: dict[str, list[dict[str, Any]]] = {}
    for row in candidates:
        plan_index = _to_int(_first_value(row, _FIELD_MAP["candidate_plan_index"]), default=-1)
        if plan_index >= 0:
            by_plan.setdefault(plan_index, []).append(row)
        retail_url = _normalize_url(_to_text(_first_value(row, _FIELD_MAP["candidate_retail_url"])))
        if retail_url:
            by_retail.setdefault(retail_url, []).append(row)
    return by_plan, by_retail


def _index_evidence(
    rows: list[dict[str, Any]],
) -> tuple[dict[tuple[str, str], list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = {}
    by_url: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        url = _normalize_url(_to_text(_first_value(row, _FIELD_MAP["evidence_url"])))
        retail_url = _normalize_url(_to_text(_first_value(row, _FIELD_MAP["evidence_retail_url"])))
        if not url:
            continue
        by_url.setdefault(url, []).append(row)
        if retail_url:
            by_pair.setdefault((url, retail_url), []).append(row)
    return by_pair, by_url


def _score_one_plan(
    plan: dict[str, Any],
    *,
    idx: int,
    topk: int,
    min_accept_score: int,
    candidates_by_plan: dict[int, list[dict[str, Any]]],
    candidates_by_retail: dict[str, list[dict[str, Any]]],
    evidence_by_pair: dict[tuple[str, str], list[dict[str, Any]]],
    evidence_by_url: dict[str, list[dict[str, Any]]],
    blocked_seen_count: dict[str, int],
) -> tuple[DecisionRecord, list[Any]]:
    plan_retail_url = _normalize_url(_to_text(_first_value(plan, _FIELD_MAP["plan_retail_url"])))
    candidates = list(candidates_by_plan.get(idx, []))
    if not candidates and plan_retail_url:
        candidates = list(candidates_by_retail.get(plan_retail_url, []))

    robots_candidates: list[dict[str, Any]] = []
    for row in candidates:
        if bool(_first_value(row, _FIELD_MAP["candidate_robots_allowed"])):
            robots_candidates.append(row)

    scored = []
    for candidate in robots_candidates:
        evidence = _lookup_evidence_for_candidate(
            candidate,
            plan_retail_url=plan_retail_url,
            evidence_by_pair=evidence_by_pair,
            evidence_by_url=evidence_by_url,
        )
        breakdown = score_candidate(plan, candidate, evidence)
        scored.append(breakdown)
        block_reason = _to_optional_text(_first_value(evidence, _FIELD_MAP["evidence_block_reason"]))
        if block_reason:
            blocked_seen_count[block_reason] = blocked_seen_count.get(block_reason, 0) + 1

    decision = select_best(
        scored,
        plan=plan,
        topk=topk,
        min_accept_score=min_accept_score,
    )
    ranked = rank_candidates(scored)
    return decision, ranked


def _lookup_evidence_for_candidate(
    candidate: dict[str, Any],
    *,
    plan_retail_url: str,
    evidence_by_pair: dict[tuple[str, str], list[dict[str, Any]]],
    evidence_by_url: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    candidate_url = _normalize_url(_to_text(_first_value(candidate, _FIELD_MAP["candidate_url"])))
    if not candidate_url:
        return {}

    candidate_retail = _normalize_url(_to_text(_first_value(candidate, _FIELD_MAP["candidate_retail_url"])))
    retail_url = candidate_retail or plan_retail_url
    if retail_url:
        rows = evidence_by_pair.get((candidate_url, retail_url), [])
        if rows:
            return rows[0]

    fallback = evidence_by_url.get(candidate_url, [])
    if fallback:
        return fallback[0]
    return {}


def _internal_error_decision(plan: dict[str, Any], *, idx: int) -> DecisionRecord:
    plan_index = _to_int(_first_value(plan, _FIELD_MAP["plan_index"]), default=idx)
    return DecisionRecord(
        plan_index=plan_index,
        retail_url=_to_text(_first_value(plan, _FIELD_MAP["plan_retail_url"])),
        retail_title=_to_text(plan.get("title")),
        source=_to_text(plan.get("source")),
        category=_to_text(plan.get("category")),
        brand_key=_to_optional_text(plan.get("brand_key")),
        decision="no_candidates",
        decision_reason="internal_error",
        chosen_official_url=None,
        confidence=0,
        top1_score=None,
        matched_tokens=[],
        top_k_summary=[],
    )


def _apply_plan_failure_reason(
    decision: DecisionRecord,
    *,
    idx: int,
    reason_by_plan_index: dict[int, str],
) -> DecisionRecord:
    if decision.decision != "no_candidates":
        return decision
    if decision.decision_reason != "no robots_allowed candidates":
        return decision

    reason = reason_by_plan_index.get(decision.plan_index)
    if reason is None:
        reason = reason_by_plan_index.get(idx)
    if not reason:
        return decision

    return DecisionRecord(
        plan_index=decision.plan_index,
        retail_url=decision.retail_url,
        retail_title=decision.retail_title,
        source=decision.source,
        category=decision.category,
        brand_key=decision.brand_key,
        decision=decision.decision,
        decision_reason=f"no_candidates: {reason}",
        chosen_official_url=decision.chosen_official_url,
        confidence=decision.confidence,
        top1_score=decision.top1_score,
        matched_tokens=list(decision.matched_tokens),
        top_k_summary=list(decision.top_k_summary),
    )


def _accumulate_decision_stats(stats: dict[str, Any], decision: DecisionRecord) -> None:
    stats[decision.decision] += 1
    if decision.top1_score is not None:
        stats["top1_score_sum"] += float(decision.top1_score)
        stats["top1_score_count"] += 1


def _print_stats(stats: dict[str, Any]) -> None:
    print(f"total_retail_items={stats['total_retail_items']}", file=sys.stderr)
    print(
        f"accepted={stats['accepted']} needs_manual_review={stats['needs_manual_review']} no_candidates={stats['no_candidates']}",
        file=sys.stderr,
    )
    if stats["top1_score_count"] > 0:
        avg_top1_score = stats["top1_score_sum"] / stats["top1_score_count"]
    else:
        avg_top1_score = 0.0
    print(f"avg_top1_score={avg_top1_score:.3f}", file=sys.stderr)
    blocked_seen = stats["blocked_seen_count"]
    if blocked_seen:
        blocked_summary = ",".join(f"{k}:{blocked_seen[k]}" for k in sorted(blocked_seen))
    else:
        blocked_summary = "none"
    print(f"blocked_seen_count={blocked_summary}", file=sys.stderr)
    print(f"errors_count={stats['errors_count']}", file=sys.stderr)


def _first_value(data: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in data:
            return data.get(key)
    return None


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
        text = value.strip()
        if not text:
            return default
        try:
            return int(text)
        except ValueError:
            return default
    return default


def _normalize_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlsplit(url)
    if not parsed.scheme and not parsed.netloc:
        return url.lower()
    normalized_host = parsed.hostname.lower() if parsed.hostname else ""
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme.lower()}://{normalized_host}{path}{query}"


if __name__ == "__main__":
    raise SystemExit(main())
