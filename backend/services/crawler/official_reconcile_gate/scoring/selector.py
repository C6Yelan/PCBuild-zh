from __future__ import annotations

import re
import unicodedata
from typing import Any
from urllib.parse import urlsplit

from .types import DecisionRecord, ScoreBreakdown

_WEAK_MATCH_TOKENS = {
    "rog",
    "tuf",
    "strix",
    "prime",
    "gaming",
    "republic",
    "gamers",
}
_LETTER_RE = re.compile(r"[a-z]", flags=re.UNICODE)
_WS_RE = re.compile(r"\s+", flags=re.UNICODE)
_PSU_WATT_RE = re.compile(r"\b\d{3,4}\s*w\b", flags=re.IGNORECASE)
_PSU_NEGATIVE_TITLE_KEYWORDS = (
    "boitier",
    "boitiers",
    "chassis",
    "case",
    "pc case",
    "tower",
    "enclosure",
)
_PSU_POSITIVE_TITLE_KEYWORDS = (
    "power supply",
    "psu",
    "80 plus",
    "atx",
    "watt",
)


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
    retail_title = _to_text(safe_plan.get("title"))
    source = _to_text(safe_plan.get("source"))
    category = _to_text(safe_plan.get("category"))
    brand_key = _to_optional_text(safe_plan.get("brand_key"))

    if not ranked:
        return DecisionRecord(
            plan_index=plan_index,
            retail_url=retail_url,
            retail_title=retail_title,
            source=source,
            category=category,
            brand_key=brand_key,
            decision="no_candidates",
            decision_reason="no robots_allowed candidates",
            chosen_official_url=None,
            confidence=0,
            top1_score=None,
            matched_tokens=[],
            top_k_summary=[],
        )

    top1 = ranked[0]
    resolved_category = category or top1.category
    resolved_brand_key = (brand_key if brand_key is not None else top1.brand_key) or ""
    top1_score = top1.total_score
    if top1_score < min_accept_score:
        decision = "needs_manual_review"
        decision_reason = f"top1_score {top1_score} < min_accept_score {min_accept_score}"
    else:
        decision = "accepted"
        decision_reason = f"top1_score {top1_score} >= min_accept_score {min_accept_score}"
        if not has_strong_match(top1.matched_tokens):
            decision = "needs_manual_review"
            decision_reason = (
                f"weak_match_only: matched_tokens={list(top1.matched_tokens)} "
                f"top1_score={top1_score} min_accept_score={min_accept_score}"
            )
        if (
            decision == "accepted"
            and resolved_category.strip().upper() == "PSU"
            and resolved_brand_key.strip().lower() == "asus"
        ):
            parsed_url = urlsplit(top1.official_url)
            host = (parsed_url.netloc or "").strip().lower()
            if host in {"rog.asus.com", "www.rog.asus.com", "asus.com", "www.asus.com"} and not _is_asus_psu_product_url(
                top1.official_url
            ):
                decision = "needs_manual_review"
                decision_reason = f"non_product_page: expected-PSU url={top1.official_url}"
            extracted_title = top1.page_title or ""
            if decision == "accepted" and not _is_psu_title_sane(extracted_title):
                decision = "needs_manual_review"
                decision_reason = f"category_mismatch: expected=PSU title={extracted_title}"

    return DecisionRecord(
        plan_index=plan_index if plan_index >= 0 else top1.plan_index,
        retail_url=retail_url or top1.retail_url,
        retail_title=retail_title,
        source=source or top1.source,
        category=resolved_category,
        brand_key=brand_key if brand_key is not None else top1.brand_key,
        decision=decision,
        decision_reason=decision_reason,
        chosen_official_url=top1.official_url,
        confidence=_score_to_confidence(top1_score),
        top1_score=top1_score,
        matched_tokens=list(top1.matched_tokens),
        top_k_summary=[
            {
                "official_url": item.official_url,
                "score": item.total_score,
                "reasons": list(item.reasons),
                "components": dict(item.components),
                "matched_tokens": list(item.matched_tokens),
            }
            for item in ranked[:summary_limit]
        ],
    )


def _score_to_confidence(score: int) -> int:
    if score <= 0:
        return 0
    return min(100, score * 20)


def is_strong_token(token: str) -> bool:
    text = (token or "").strip().lower()
    if len(text) < 4:
        return False
    if text in _WEAK_MATCH_TOKENS:
        return False
    if _LETTER_RE.search(text) is None:
        return False
    return True


def has_strong_match(matched_tokens: list[str]) -> bool:
    for token in matched_tokens:
        if isinstance(token, str) and is_strong_token(token):
            return True
    return False


def _normalize_for_match(text: str) -> str:
    if not text:
        return ""
    normalized = unicodedata.normalize("NFKD", text)
    ascii_like = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    lowered = ascii_like.lower()
    return _WS_RE.sub(" ", lowered).strip()


def _is_psu_title_sane(title: str) -> bool:
    normalized = _normalize_for_match(title)
    if not normalized:
        return False
    if any(keyword in normalized for keyword in _PSU_NEGATIVE_TITLE_KEYWORDS):
        return False
    if any(keyword in normalized for keyword in _PSU_POSITIVE_TITLE_KEYWORDS):
        return True
    return _PSU_WATT_RE.search(normalized) is not None


def _is_asus_psu_product_url(url: str) -> bool:
    parsed = urlsplit(url)
    host = (parsed.netloc or "").strip().lower()
    path = (parsed.path or "/").lower()
    if host in {"rog.asus.com", "www.rog.asus.com"}:
        return "/power-supply-units/" in path
    if host in {"asus.com", "www.asus.com"}:
        return "/power-supply-units/" in path or "/motherboards-components/power-supply-units/" in path
    return False


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
