from __future__ import annotations

from dataclasses import dataclass
from itertools import product
import json
import math
import re
from typing import Any, Mapping, Sequence

from backend.services.chat.build_policy import (
    BuildRequestProfile,
    classify_candidate,
    estimate_required_psu_wattage,
    evaluate_build_selection_compatibility,
)
from backend.services.chat.context_pack.retrieval import CandidatePart, P1RetrievalResult
from backend.services.chat.contracts import NormalizedDemand

_CORE_BUILD_CATEGORIES = ("CPU", "GPU", "MB", "RAM", "SSD", "PSU", "CASE")
_MAX_COMPONENT_OPTIONS = 4
_MAX_COMBINATIONS = 4096
_TOP_COMPONENTS_PER_CATEGORY = 3
_TOP_REJECTED_BUILDS = 5
_CHIPSET_LOW_PREFIXES = ("A", "H", "B4")
_CHIPSET_MAINSTREAM_PREFIXES = ("B",)
_CHIPSET_HIGH_PREFIXES = ("X", "Z")


@dataclass(frozen=True, slots=True)
class ScoredComponent:
    part: CandidatePart
    score: float
    notes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BuildScoreBreakdown:
    compatibility_score: float
    semantic_cleanliness_score: float
    budget_utilization_score: float
    gpu_priority_score: float
    cpu_gpu_balance_score: float
    motherboard_tier_match_score: float
    ram_reasonableness_score: float
    storage_reasonableness_score: float
    psu_reasonableness_score: float
    total_score: float

    def as_dict(self) -> dict[str, float]:
        return {
            "compatibility_score": round(self.compatibility_score, 2),
            "semantic_cleanliness_score": round(self.semantic_cleanliness_score, 2),
            "budget_utilization_score": round(self.budget_utilization_score, 2),
            "gpu_priority_score": round(self.gpu_priority_score, 2),
            "cpu_gpu_balance_score": round(self.cpu_gpu_balance_score, 2),
            "motherboard_tier_match_score": round(self.motherboard_tier_match_score, 2),
            "ram_reasonableness_score": round(self.ram_reasonableness_score, 2),
            "storage_reasonableness_score": round(self.storage_reasonableness_score, 2),
            "psu_reasonableness_score": round(self.psu_reasonableness_score, 2),
            "total_score": round(self.total_score, 2),
        }


@dataclass(frozen=True, slots=True)
class ScoredBuildCandidate:
    parts_by_category: dict[str, CandidatePart]
    total_price: int | None
    breakdown: BuildScoreBreakdown
    applied_penalties: tuple[str, ...]
    applied_warnings: tuple[str, ...]
    candidate_rejection_reasons: tuple[str, ...]
    reasoning: tuple[str, ...]
    assessment: str

    def as_summary(self) -> dict[str, Any]:
        return {
            "assessment": self.assessment,
            "total_build_price": self.total_price,
            "score_breakdown": self.breakdown.as_dict(),
            "applied_penalties": list(self.applied_penalties),
            "applied_warnings": list(self.applied_warnings),
            "candidate_rejection_reasons": list(self.candidate_rejection_reasons),
            "reasoning": list(self.reasoning),
            "parts": {
                category: _part_summary(part)
                for category, part in sorted(self.parts_by_category.items())
            },
        }


@dataclass(frozen=True, slots=True)
class BuildScoringResult:
    retrieval_result: P1RetrievalResult
    context_meta: dict[str, Any] | None
    selected_candidate: ScoredBuildCandidate | None
    rejected_candidates: tuple[ScoredBuildCandidate, ...]


def apply_build_scoring(
    retrieval_result: Any,
    *,
    profile: BuildRequestProfile,
    normalized_demand: NormalizedDemand | None,
) -> BuildScoringResult:
    items_by_category = getattr(retrieval_result, "items_by_category", None)
    if not profile.enabled or not isinstance(items_by_category, Mapping):
        return BuildScoringResult(
            retrieval_result=_as_retrieval_result(retrieval_result),
            context_meta=None,
            selected_candidate=None,
            rejected_candidates=(),
        )

    requested_categories = [
        category
        for category in _CORE_BUILD_CATEGORIES
        if category in items_by_category
        and (
            normalized_demand is None
            or not normalized_demand.categories
            or category in normalized_demand.categories
        )
    ]
    if len(requested_categories) < 3:
        return BuildScoringResult(
            retrieval_result=_as_retrieval_result(retrieval_result),
            context_meta=None,
            selected_candidate=None,
            rejected_candidates=(),
        )

    usage_profile = (
        normalized_demand.usage_profile
        if normalized_demand is not None and normalized_demand.usage_profile
        else profile.usage_profile
    ) or "unknown"
    component_scores = _rank_components(
        items_by_category=items_by_category,
        requested_categories=requested_categories,
        profile=profile,
        normalized_demand=normalized_demand,
        usage_profile=usage_profile,
    )
    reranked_items = {
        category: [scored.part for scored in component_scores.get(category, ())]
        for category in items_by_category.keys()
    }
    reranked_result = P1RetrievalResult(items_by_category=reranked_items)

    selected_candidate: ScoredBuildCandidate | None = None
    rejected_candidates: tuple[ScoredBuildCandidate, ...] = ()

    if "CPU" in requested_categories and "GPU" in requested_categories:
        selected_candidate, rejected_candidates = _evaluate_build_candidates(
            component_scores=component_scores,
            requested_categories=requested_categories,
            profile=profile,
            usage_profile=usage_profile,
        )

    missing_categories = sorted(
        category for category in requested_categories if not component_scores.get(category)
    )
    context_meta = _build_context_meta(
        requested_categories=requested_categories,
        usage_profile=usage_profile,
        profile=profile,
        component_scores=component_scores,
        selected_candidate=selected_candidate,
        rejected_candidates=rejected_candidates,
        missing_categories=missing_categories,
    )
    return BuildScoringResult(
        retrieval_result=reranked_result,
        context_meta=context_meta,
        selected_candidate=selected_candidate,
        rejected_candidates=rejected_candidates,
    )


def build_scoring_message(build_scoring: Mapping[str, Any] | None) -> str | None:
    if not isinstance(build_scoring, Mapping) or not build_scoring:
        return None
    return json.dumps(dict(build_scoring), ensure_ascii=False, sort_keys=True, indent=2)


def _as_retrieval_result(retrieval_result: Any) -> P1RetrievalResult:
    if isinstance(retrieval_result, P1RetrievalResult):
        return retrieval_result
    items_by_category = getattr(retrieval_result, "items_by_category", {}) or {}
    return P1RetrievalResult(items_by_category={category: list(items) for category, items in items_by_category.items()})


def _part_summary(part: CandidatePart) -> dict[str, Any]:
    return {
        "part_id": part.part_id,
        "display_name": part.display_name,
        "price": part.price,
    }


def _rank_components(
    *,
    items_by_category: Mapping[str, Sequence[CandidatePart]],
    requested_categories: Sequence[str],
    profile: BuildRequestProfile,
    normalized_demand: NormalizedDemand | None,
    usage_profile: str,
) -> dict[str, tuple[ScoredComponent, ...]]:
    category_price_map = {
        category: sorted(_price(part) for part in items if _price(part) is not None)
        for category, items in items_by_category.items()
    }
    platform_price_map = _motherboard_platform_price_map(items_by_category)
    ranked: dict[str, tuple[ScoredComponent, ...]] = {}
    for category, items in items_by_category.items():
        scored_items: list[ScoredComponent] = []
        for item in items:
            score, notes = _score_component(
                item,
                category=category,
                profile=profile,
                normalized_demand=normalized_demand,
                usage_profile=usage_profile,
                category_price_map=category_price_map,
                platform_price_map=platform_price_map,
                requested_categories=requested_categories,
            )
            scored_items.append(
                ScoredComponent(
                    part=item,
                    score=score,
                    notes=tuple(notes),
                )
            )
        ranked[category] = tuple(
            sorted(
                scored_items,
                key=lambda item: (
                    -item.score,
                    _sortable_price(item.part),
                    item.part.display_name,
                    item.part.part_id,
                ),
            )
        )
    return ranked


def _score_component(
    part: CandidatePart,
    *,
    category: str,
    profile: BuildRequestProfile,
    normalized_demand: NormalizedDemand | None,
    usage_profile: str,
    category_price_map: Mapping[str, Sequence[int]],
    platform_price_map: Mapping[str, Sequence[int]],
    requested_categories: Sequence[str],
) -> tuple[float, list[str]]:
    score = 60.0
    notes: list[str] = []
    price = _price(part)
    target_total = profile.target_total_price or profile.budget_target or profile.budget_max
    share = (price / target_total) if price is not None and target_total else None

    if category == "GPU":
        if usage_profile == "gaming":
            gpu_share_score = _band_score(share, soft_low=0.35, soft_high=0.55, hard_low=0.18, hard_high=0.7)
            score += (gpu_share_score - 60.0) * 0.55
            if gpu_share_score >= 90:
                notes.append("gpu_budget_share_good")
            elif gpu_share_score < 45:
                notes.append("gpu_budget_share_low")
        tier = _gpu_tier(part)
        score += (tier - 2.5) * 8.0
        if normalized_demand is not None and normalized_demand.preferred_gpu_vendor:
            if _vendor_matches(part, normalized_demand.preferred_gpu_vendor):
                score += 6.0
                notes.append("gpu_vendor_match")
    elif category == "CPU":
        if usage_profile == "gaming":
            cpu_share_score = _band_score(share, soft_low=0.14, soft_high=0.24, hard_low=0.08, hard_high=0.34)
            score += (cpu_share_score - 60.0) * 0.45
            if cpu_share_score < 45:
                notes.append("cpu_budget_share_high")
        tier = _cpu_tier(part)
        score += (3.4 - abs(tier - 3.4)) * 4.0
        if normalized_demand is not None and normalized_demand.preferred_cpu_vendor:
            if _vendor_matches(part, normalized_demand.preferred_cpu_vendor):
                score += 6.0
                notes.append("cpu_vendor_match")
    elif category == "MB":
        socket = _socket_hint(part)
        platform_prices = platform_price_map.get(socket or "", ())
        percentile = _price_percentile(price, platform_prices)
        share_score = _band_score(share, soft_low=0.08, soft_high=0.16, hard_low=0.04, hard_high=0.26)
        score += (share_score - 60.0) * 0.35
        score += (_motherboard_tier(part, percentile=percentile) - 3.0) * 8.0
        chipset = _chipset_hint(part)
        if usage_profile == "gaming" and chipset.startswith("B"):
            score += 5.0
            notes.append("mainstream_chipset")
    elif category == "RAM":
        capacity_gb = _capacity_gb(part)
        price_score = _band_score(share, soft_low=0.05, soft_high=0.10, hard_low=0.03, hard_high=0.18)
        score += (price_score - 60.0) * 0.45
        if capacity_gb == 32:
            score += 12.0
            notes.append("ram_32gb_sweet_spot")
        elif capacity_gb == 16:
            score += 6.0
        elif capacity_gb is not None and capacity_gb > 32:
            score -= 10.0
            notes.append("ram_capacity_overkill")
    elif category == "SSD":
        capacity_gb = _capacity_gb(part)
        price_score = _band_score(share, soft_low=0.05, soft_high=0.09, hard_low=0.02, hard_high=0.15)
        score += (price_score - 60.0) * 0.4
        if capacity_gb is not None:
            if 900 <= capacity_gb <= 2200:
                score += 8.0
                notes.append("ssd_capacity_good")
            elif capacity_gb > 2200:
                score -= 5.0
                notes.append("ssd_capacity_high")
    elif category == "PSU":
        wattage = _wattage(part)
        price_score = _band_score(share, soft_low=0.05, soft_high=0.09, hard_low=0.03, hard_high=0.16)
        score += (price_score - 60.0) * 0.35
        if wattage is not None and 650 <= wattage <= 850:
            score += 8.0
            notes.append("psu_wattage_midrange")
    elif category == "CASE":
        price_score = _band_score(share, soft_low=0.04, soft_high=0.10, hard_low=0.02, hard_high=0.16)
        score += (price_score - 60.0) * 0.35

    prices = category_price_map.get(category, ())
    percentile = _price_percentile(price, prices)
    if percentile is not None:
        if category == "GPU":
            score += percentile * 10.0
        elif category in {"RAM", "SSD", "PSU", "CASE"}:
            score += (0.55 - abs(percentile - 0.55)) * 6.0
        elif category == "CPU":
            score += (0.5 - abs(percentile - 0.55)) * 8.0

    if category not in requested_categories:
        score -= 8.0
    return _clamp(score, 0.0, 100.0), notes


def _evaluate_build_candidates(
    *,
    component_scores: Mapping[str, Sequence[ScoredComponent]],
    requested_categories: Sequence[str],
    profile: BuildRequestProfile,
    usage_profile: str,
) -> tuple[ScoredBuildCandidate | None, tuple[ScoredBuildCandidate, ...]]:
    selected_pool = {
        category: list(scored_items[:_MAX_COMPONENT_OPTIONS])
        for category, scored_items in component_scores.items()
        if category in requested_categories and scored_items
    }
    if any(category not in selected_pool for category in requested_categories):
        return None, ()

    combination_count = 1
    for items in selected_pool.values():
        combination_count *= max(1, len(items))
    while combination_count > _MAX_COMBINATIONS:
        longest_category = max(selected_pool, key=lambda key: len(selected_pool[key]))
        if len(selected_pool[longest_category]) <= 2:
            break
        selected_pool[longest_category] = selected_pool[longest_category][:-1]
        combination_count = 1
        for items in selected_pool.values():
            combination_count *= max(1, len(items))

    candidates: list[ScoredBuildCandidate] = []
    rejected: list[ScoredBuildCandidate] = []
    ordered_categories = [category for category in requested_categories if category in selected_pool]
    for combination in product(*(selected_pool[category] for category in ordered_categories)):
        parts = {category: scored.part for category, scored in zip(ordered_categories, combination)}
        component_score_map = {category: scored.score for category, scored in zip(ordered_categories, combination)}
        candidate = _score_build_candidate(
            parts_by_category=parts,
            profile=profile,
            usage_profile=usage_profile,
            component_score_map=component_score_map,
        )
        if candidate.candidate_rejection_reasons:
            rejected.append(candidate)
            continue
        candidates.append(candidate)

    selected_candidate = max(candidates, key=lambda candidate: candidate.breakdown.total_score, default=None)
    ranked_rejected = tuple(
        sorted(
            rejected,
            key=lambda candidate: (
                -candidate.breakdown.total_score,
                len(candidate.candidate_rejection_reasons),
                candidate.total_price or math.inf,
            ),
        )[:_TOP_REJECTED_BUILDS]
    )
    return selected_candidate, ranked_rejected


def _score_build_candidate(
    *,
    parts_by_category: Mapping[str, CandidatePart],
    profile: BuildRequestProfile,
    usage_profile: str,
    component_score_map: Mapping[str, float],
) -> ScoredBuildCandidate:
    compatibility_reasons = evaluate_build_selection_compatibility(parts_by_category)
    prices = [_price(part) for part in parts_by_category.values() if _price(part) is not None]
    total_price = sum(prices) if prices and len(prices) == len(parts_by_category) else None
    applied_penalties: list[str] = []
    applied_warnings: list[str] = []
    candidate_rejection_reasons: list[str] = list(compatibility_reasons)

    compatibility_score = 100.0 if not compatibility_reasons else 0.0
    semantic_cleanliness_score = 100.0

    budget_utilization_score = _budget_utilization_score(
        total_price,
        profile=profile,
        applied_penalties=applied_penalties,
        applied_warnings=applied_warnings,
        candidate_rejection_reasons=candidate_rejection_reasons,
    )
    gpu_priority_score = _gpu_priority_score(
        parts_by_category,
        usage_profile=usage_profile,
        applied_penalties=applied_penalties,
    )
    cpu_gpu_balance_score = _cpu_gpu_balance_score(
        parts_by_category,
        usage_profile=usage_profile,
        applied_penalties=applied_penalties,
    )
    motherboard_tier_match_score = _motherboard_tier_match_score(
        parts_by_category,
        applied_penalties=applied_penalties,
        applied_warnings=applied_warnings,
    )
    ram_reasonableness_score = _ram_reasonableness_score(
        parts_by_category,
        applied_penalties=applied_penalties,
    )
    storage_reasonableness_score = _storage_reasonableness_score(
        parts_by_category,
        applied_penalties=applied_penalties,
    )
    psu_reasonableness_score = _psu_reasonableness_score(
        parts_by_category,
        applied_penalties=applied_penalties,
        applied_warnings=applied_warnings,
        candidate_rejection_reasons=candidate_rejection_reasons,
    )

    component_fit_score = (
        sum(component_score_map.values()) / len(component_score_map)
        if component_score_map
        else 60.0
    )
    total_score = (
        compatibility_score * 0.16
        + semantic_cleanliness_score * 0.06
        + budget_utilization_score * 0.20
        + gpu_priority_score * 0.18
        + cpu_gpu_balance_score * 0.16
        + motherboard_tier_match_score * 0.12
        + ram_reasonableness_score * 0.05
        + storage_reasonableness_score * 0.03
        + psu_reasonableness_score * 0.02
        + component_fit_score * 0.02
    )
    breakdown = BuildScoreBreakdown(
        compatibility_score=compatibility_score,
        semantic_cleanliness_score=semantic_cleanliness_score,
        budget_utilization_score=budget_utilization_score,
        gpu_priority_score=gpu_priority_score,
        cpu_gpu_balance_score=cpu_gpu_balance_score,
        motherboard_tier_match_score=motherboard_tier_match_score,
        ram_reasonableness_score=ram_reasonableness_score,
        storage_reasonableness_score=storage_reasonableness_score,
        psu_reasonableness_score=psu_reasonableness_score,
        total_score=_clamp(total_score, 0.0, 100.0),
    )
    reasoning = _build_reasoning(
        breakdown=breakdown,
        applied_penalties=applied_penalties,
        applied_warnings=applied_warnings,
    )
    return ScoredBuildCandidate(
        parts_by_category=dict(parts_by_category),
        total_price=total_price,
        breakdown=breakdown,
        applied_penalties=tuple(sorted(set(applied_penalties))),
        applied_warnings=tuple(sorted(set(applied_warnings))),
        candidate_rejection_reasons=tuple(sorted(set(candidate_rejection_reasons))),
        reasoning=tuple(reasoning),
        assessment=_assessment_text(breakdown, candidate_rejection_reasons),
    )


def _budget_utilization_score(
    total_price: int | None,
    *,
    profile: BuildRequestProfile,
    applied_penalties: list[str],
    applied_warnings: list[str],
    candidate_rejection_reasons: list[str],
) -> float:
    if total_price is None:
        applied_warnings.append("missing_build_price")
        return 45.0
    if profile.budget_max is not None and total_price > profile.budget_max:
        candidate_rejection_reasons.append("over_budget")
        applied_penalties.append("over_budget")
        return 0.0
    if profile.target_total_price is None:
        return 70.0

    target = profile.target_total_price
    minimum = profile.minimum_budget_utilization
    if minimum is not None and total_price < minimum:
        applied_penalties.append("under_minimum_budget_utilization")
        applied_warnings.append("candidate_pool_underutilized")
        floor = max(1, int(round(minimum * 0.8)))
        return _band_score(total_price, soft_low=minimum, soft_high=target + 1500, hard_low=floor, hard_high=target + 5000)
    return _band_score(total_price, soft_low=max(1, target - 1500), soft_high=target + 1500, hard_low=max(1, target - 7000), hard_high=(profile.budget_max or target) + 2500)


def _gpu_priority_score(
    parts_by_category: Mapping[str, CandidatePart],
    *,
    usage_profile: str,
    applied_penalties: list[str],
) -> float:
    if usage_profile != "gaming":
        return 70.0
    gpu_price = _price(parts_by_category.get("GPU"))
    cpu_price = _price(parts_by_category.get("CPU"))
    ram_price = _price(parts_by_category.get("RAM"))
    mb_price = _price(parts_by_category.get("MB"))
    prices = [price for price in (gpu_price, cpu_price, ram_price, mb_price) if price is not None]
    if gpu_price is None or not prices:
        return 50.0
    largest_price = max(prices)
    score = 100.0 if gpu_price >= largest_price else 68.0
    if cpu_price is not None and gpu_price < cpu_price:
        score -= 25.0
        applied_penalties.append("gpu_not_primary_budget_item")
    if ram_price is not None and gpu_price < ram_price * 1.5:
        score -= 18.0
        applied_penalties.append("ram_spend_crowds_out_gpu")
    if mb_price is not None and gpu_price < mb_price * 1.8:
        score -= 8.0
    return _clamp(score, 0.0, 100.0)


def _cpu_gpu_balance_score(
    parts_by_category: Mapping[str, CandidatePart],
    *,
    usage_profile: str,
    applied_penalties: list[str],
) -> float:
    if usage_profile != "gaming":
        return 70.0
    cpu_price = _price(parts_by_category.get("CPU"))
    gpu_price = _price(parts_by_category.get("GPU"))
    if cpu_price is None or gpu_price is None:
        return 50.0
    ratio = gpu_price / max(1, cpu_price)
    score = _band_score(ratio, soft_low=1.15, soft_high=2.3, hard_low=0.7, hard_high=3.4)
    if ratio < 1.0:
        applied_penalties.append("cpu_more_expensive_than_gpu")
    return score


def _motherboard_tier_match_score(
    parts_by_category: Mapping[str, CandidatePart],
    *,
    applied_penalties: list[str],
    applied_warnings: list[str],
) -> float:
    cpu = parts_by_category.get("CPU")
    motherboard = parts_by_category.get("MB")
    if cpu is None or motherboard is None:
        return 55.0
    cpu_tier = _cpu_tier(cpu)
    mb_tier = _motherboard_tier(motherboard, percentile=None)
    expected = _clamp(cpu_tier - 0.6, 2.2, 4.5)
    diff = mb_tier - expected
    score = 100.0 - abs(diff) * 28.0
    if diff < -0.9:
        applied_penalties.append("motherboard_tier_too_low_for_cpu")
    elif diff > 1.2:
        applied_warnings.append("motherboard_spend_high_for_cpu")
    chipset = _chipset_hint(motherboard)
    if cpu_tier >= 4.2 and _chipset_class(chipset) <= 1.8:
        score -= 25.0
        applied_penalties.append("entry_motherboard_with_high_cpu")
    if 3.0 <= cpu_tier <= 4.2 and chipset.startswith("B"):
        score += 8.0
    return _clamp(score, 0.0, 100.0)


def _ram_reasonableness_score(
    parts_by_category: Mapping[str, CandidatePart],
    *,
    applied_penalties: list[str],
) -> float:
    ram = parts_by_category.get("RAM")
    total_price = _total_price(parts_by_category)
    if ram is None:
        return 55.0
    capacity = _capacity_gb(ram)
    ram_price = _price(ram)
    share = (ram_price / total_price) if ram_price is not None and total_price else None
    score = _band_score(share, soft_low=0.05, soft_high=0.10, hard_low=0.03, hard_high=0.18)
    if capacity == 32:
        score += 10.0
    elif capacity == 16:
        score += 4.0
    elif capacity is not None and capacity > 32:
        score -= 18.0
        applied_penalties.append("ram_capacity_overkill_for_gaming")
    return _clamp(score, 0.0, 100.0)


def _storage_reasonableness_score(
    parts_by_category: Mapping[str, CandidatePart],
    *,
    applied_penalties: list[str],
) -> float:
    storage = parts_by_category.get("SSD")
    total_price = _total_price(parts_by_category)
    if storage is None:
        return 55.0
    capacity = _capacity_gb(storage)
    storage_price = _price(storage)
    share = (storage_price / total_price) if storage_price is not None and total_price else None
    score = _band_score(share, soft_low=0.04, soft_high=0.09, hard_low=0.02, hard_high=0.16)
    if capacity is not None and capacity < 900:
        score -= 10.0
    elif capacity is not None and capacity > 2200:
        score -= 12.0
        applied_penalties.append("storage_spend_high")
    return _clamp(score, 0.0, 100.0)


def _psu_reasonableness_score(
    parts_by_category: Mapping[str, CandidatePart],
    *,
    applied_penalties: list[str],
    applied_warnings: list[str],
    candidate_rejection_reasons: list[str],
) -> float:
    psu = parts_by_category.get("PSU")
    if psu is None:
        return 55.0
    wattage = _wattage(psu)
    required = estimate_required_psu_wattage(
        cpu=parts_by_category.get("CPU"),
        gpu=parts_by_category.get("GPU"),
    )
    if wattage is None or required is None:
        applied_warnings.append("psu_requirement_unknown")
        return 65.0
    if wattage < required:
        candidate_rejection_reasons.append("psu_capacity")
        applied_penalties.append("psu_below_required_headroom")
        return 0.0
    ratio = wattage / max(1, required)
    score = _band_score(ratio, soft_low=1.15, soft_high=1.65, hard_low=1.0, hard_high=2.4)
    if ratio > 2.0:
        applied_penalties.append("psu_oversized_for_build")
    return _clamp(score, 0.0, 100.0)


def _build_reasoning(
    *,
    breakdown: BuildScoreBreakdown,
    applied_penalties: Sequence[str],
    applied_warnings: Sequence[str],
) -> list[str]:
    reasoning: list[str] = []
    if breakdown.gpu_priority_score >= 80:
        reasoning.append("GPU 仍是主要預算項，沒有被 CPU 或 RAM 明顯擠壓。")
    if breakdown.cpu_gpu_balance_score >= 80:
        reasoning.append("CPU 與 GPU 的價位落點接近遊戲機常見平衡，不是高價 CPU 配弱顯卡。")
    if breakdown.motherboard_tier_match_score >= 80:
        reasoning.append("主機板層級和 CPU 平台搭配協調，沒有用明顯入門板去撐高階 CPU。")
    if breakdown.ram_reasonableness_score >= 80:
        reasoning.append("RAM 容量與價格維持在合理區間，沒有異常吃掉預算。")
    if "candidate_pool_underutilized" in applied_warnings:
        reasoning.append("目前 clean 候選不足以把預算有效推到目標區間，應保守說明條件限制。")
    if "motherboard_tier_too_low_for_cpu" in applied_penalties:
        reasoning.append("主機板層級偏低，雖然相容但不建議當首選。")
    if "ram_capacity_overkill_for_gaming" in applied_penalties:
        reasoning.append("RAM 容量或價格偏高，對這類遊戲機屬於過度配置。")
    return reasoning[:4]


def _assessment_text(
    breakdown: BuildScoreBreakdown,
    candidate_rejection_reasons: Sequence[str],
) -> str:
    if candidate_rejection_reasons:
        return "這組配單不建議作為首選，主要是因為預算或相容性限制。"
    if breakdown.total_score >= 82:
        return "這是一組整體分配合理的 gaming build。"
    if breakdown.total_score >= 68:
        return "這是一組可用但有明顯取捨的 gaming build。"
    return "這組配單雖然可相容，但整體分配偏失衡或候選受限。"


def _build_context_meta(
    *,
    requested_categories: Sequence[str],
    usage_profile: str,
    profile: BuildRequestProfile,
    component_scores: Mapping[str, Sequence[ScoredComponent]],
    selected_candidate: ScoredBuildCandidate | None,
    rejected_candidates: Sequence[ScoredBuildCandidate],
    missing_categories: Sequence[str],
) -> dict[str, Any]:
    return {
        "build_profile": profile.request_mode,
        "usage_profile": usage_profile,
        "target_total_price": profile.target_total_price,
        "minimum_budget_utilization": profile.minimum_budget_utilization,
        "requested_categories": list(requested_categories),
        "missing_categories": list(missing_categories),
        "selected_build": selected_candidate.as_summary() if selected_candidate is not None else None,
        "rejected_builds": [candidate.as_summary() for candidate in rejected_candidates],
        "component_rankings": {
            category: [
                {
                    "part_id": scored.part.part_id,
                    "display_name": scored.part.display_name,
                    "price": scored.part.price,
                    "score": round(scored.score, 2),
                    "notes": list(scored.notes),
                }
                for scored in component_scores.get(category, ())[:_TOP_COMPONENTS_PER_CATEGORY]
            ]
            for category in requested_categories
            if component_scores.get(category)
        },
        "candidate_pool_warning": _candidate_pool_warning(
            selected_candidate=selected_candidate,
            missing_categories=missing_categories,
        ),
    }


def _candidate_pool_warning(
    *,
    selected_candidate: ScoredBuildCandidate | None,
    missing_categories: Sequence[str],
) -> str | None:
    if missing_categories:
        return f"clean 候選不足：缺少 {', '.join(missing_categories)}"
    if selected_candidate is None:
        return "clean 候選不足或 exact combo 無法同時滿足相容與預算。"
    if "candidate_pool_underutilized" in selected_candidate.applied_warnings:
        return "clean 候選不足以有效利用預算，回答應保守說明條件限制。"
    return None


def _motherboard_platform_price_map(
    items_by_category: Mapping[str, Sequence[CandidatePart]],
) -> dict[str, list[int]]:
    price_map: dict[str, list[int]] = {}
    for motherboard in items_by_category.get("MB", ()):
        socket = _socket_hint(motherboard)
        price = _price(motherboard)
        if not socket or price is None:
            continue
        price_map.setdefault(socket, []).append(price)
    for prices in price_map.values():
        prices.sort()
    return price_map


def _total_price(parts_by_category: Mapping[str, CandidatePart]) -> int | None:
    prices = [_price(part) for part in parts_by_category.values() if part is not None]
    if not prices or len(prices) != len(parts_by_category):
        return None
    return sum(prices)


def _price(part: CandidatePart | None) -> int | None:
    if part is None:
        return None
    value = getattr(part, "price", None)
    if value is None or isinstance(value, bool):
        return None
    return int(value)


def _sortable_price(part: CandidatePart) -> int:
    price = _price(part)
    return price if price is not None else math.inf


def _price_percentile(price: int | None, prices: Sequence[int]) -> float | None:
    if price is None or not prices:
        return None
    sorted_prices = list(prices)
    less_equal = sum(1 for value in sorted_prices if value <= price)
    return less_equal / len(sorted_prices)


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).strip().split())


def _search_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(round(value))
    match = re.search(r"\d+", _normalize_text(value))
    return int(match.group(0)) if match else None


def _spec(part: CandidatePart, key: str) -> Any:
    specs = part.key_specs if isinstance(part.key_specs, Mapping) else {}
    return specs.get(key)


def _socket_hint(part: CandidatePart) -> str | None:
    for key in ("socket_hint", "socket"):
        value = _normalize_text(_spec(part, key)).upper().replace("SOCKET", "").strip()
        if value:
            return value
    return None


def _chipset_hint(part: CandidatePart) -> str:
    return _normalize_text(_spec(part, "chipset_hint") or _spec(part, "chipset")).upper()


def _chipset_class(chipset: str) -> float:
    token = chipset.upper()
    if not token:
        return 3.0
    if token.startswith(_CHIPSET_HIGH_PREFIXES):
        return 4.4
    if token.startswith(_CHIPSET_MAINSTREAM_PREFIXES):
        return 3.2
    if token.startswith(_CHIPSET_LOW_PREFIXES):
        return 1.8
    return 3.0


def _motherboard_tier(part: CandidatePart, *, percentile: float | None) -> float:
    chipset = _chipset_hint(part)
    tier = _chipset_class(chipset)
    if percentile is not None:
        tier += (percentile - 0.5) * 1.2
    if _normalize_text(_spec(part, "wifi_hint")).lower() in {"true", "yes", "1"}:
        tier += 0.2
    pcie_gen = _search_int(_spec(part, "pcie_gen_hint"))
    if pcie_gen is not None and pcie_gen >= 5:
        tier += 0.2
    return _clamp(tier, 1.0, 5.0)


def _capacity_gb(part: CandidatePart) -> int | None:
    keys = (
        "capacity_gb_hint",
        "capacity_gb",
        "capacity_gib",
        "per_dimm_gb_hint",
    )
    for key in keys:
        value = _search_int(_spec(part, key))
        if value is not None:
            if key == "per_dimm_gb_hint":
                dimms = _search_int(_spec(part, "kit_dimms_hint")) or 1
                return value * dimms
            return value
    return None


def _wattage(part: CandidatePart) -> int | None:
    return _search_int(_spec(part, "wattage_w_hint") or _spec(part, "wattage_w"))


def _vendor_matches(part: CandidatePart, vendor: str) -> bool:
    vendor_upper = vendor.upper()
    display_name = part.display_name.upper()
    specs = part.key_specs if isinstance(part.key_specs, Mapping) else {}
    brand_values = " ".join(_normalize_text(value).upper() for value in specs.values())
    haystack = f"{display_name} {brand_values}"
    return vendor_upper in haystack


def _cpu_tier(part: CandidatePart) -> float:
    haystack = part.display_name.upper()
    if "RYZEN 9" in haystack or re.search(r"\bI9\b", haystack):
        return 4.9
    if "RYZEN 7" in haystack or re.search(r"\bI7\b", haystack) or "ULTRA 7" in haystack:
        return 4.1
    if "RYZEN 5" in haystack or re.search(r"\bI5\b", haystack) or "ULTRA 5" in haystack:
        return 3.2
    if "RYZEN 3" in haystack or re.search(r"\bI3\b", haystack):
        return 2.2
    price = _price(part)
    if price is None:
        return 3.0
    if price >= 16000:
        return 4.8
    if price >= 11000:
        return 4.2
    if price >= 7000:
        return 3.4
    if price >= 4000:
        return 2.6
    return 2.0


def _gpu_tier(part: CandidatePart) -> float:
    haystack = part.display_name.upper()
    if any(token in haystack for token in ("5090", "4090", "7900 XTX")):
        return 5.0
    if any(token in haystack for token in ("5080", "4080", "7900 XT")):
        return 4.6
    if any(token in haystack for token in ("5070 TI", "4070 TI", "7800 XT")):
        return 4.1
    if any(token in haystack for token in ("5070", "4070", "7700 XT")):
        return 3.7
    if any(token in haystack for token in ("5060 TI", "4060 TI", "7600 XT", "B580")):
        return 3.2
    if any(token in haystack for token in ("5060", "4060", "7600", "B570")):
        return 2.8
    price = _price(part)
    if price is None:
        return 3.0
    if price >= 30000:
        return 4.8
    if price >= 22000:
        return 4.2
    if price >= 16000:
        return 3.7
    if price >= 11000:
        return 3.0
    return 2.3


def _band_score(
    value: float | int | None,
    *,
    soft_low: float,
    soft_high: float,
    hard_low: float,
    hard_high: float,
) -> float:
    if value is None:
        return 55.0
    numeric = float(value)
    if numeric <= hard_low or numeric >= hard_high:
        return 0.0
    if soft_low <= numeric <= soft_high:
        return 100.0
    if numeric < soft_low:
        return 100.0 * (numeric - hard_low) / max(soft_low - hard_low, 1e-6)
    return 100.0 * (hard_high - numeric) / max(hard_high - soft_high, 1e-6)


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


__all__ = [
    "BuildScoringResult",
    "apply_build_scoring",
    "build_scoring_message",
]
