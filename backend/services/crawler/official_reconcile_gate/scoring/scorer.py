from __future__ import annotations

import re
from typing import Any

from .types import ScoreBreakdown

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+", flags=re.UNICODE)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", flags=re.IGNORECASE | re.DOTALL)
_WS_RE = re.compile(r"\s+", flags=re.UNICODE)

_FIELD_MAP = {
    "plan_index": ("plan_index",),
    "retail_url": ("retail_url", "url"),
    "source": ("source",),
    "category": ("category",),
    "brand_key": ("brand_key",),
    "query_terms": ("query_terms",),
    "candidate_url": ("official_url", "candidate_url", "url"),
    "candidate_score": ("score",),
    "candidate_matched_tokens": ("matched_tokens",),
    "evidence_body_snippet": ("body_snippet",),
    "evidence_content_type": ("content_type",),
    "evidence_block_reason": ("block_reason",),
    "evidence_matched_tokens": ("matched_tokens",),
}

_WEIGHT_EVIDENCE_MATCHED = 1
_WEIGHT_TITLE_TOKEN_HIT = 2
_PENALTY_BLOCKED = 4
_PENALTY_NON_HTML = 2
_PENALTY_SHORT_SNIPPET = 1
_SHORT_SNIPPET_THRESHOLD = 80


def score_candidate(
    plan: dict[str, Any],
    candidate: dict[str, Any],
    evidence: dict[str, Any] | None,
) -> ScoreBreakdown:
    safe_plan = plan if isinstance(plan, dict) else {}
    safe_candidate = candidate if isinstance(candidate, dict) else {}
    safe_evidence = evidence if isinstance(evidence, dict) else {}

    plan_index = _to_int(_first_value(safe_plan, _FIELD_MAP["plan_index"]), default=-1)
    retail_url = _to_string(_first_value(safe_plan, _FIELD_MAP["retail_url"]))
    source = _to_string(_first_value(safe_plan, _FIELD_MAP["source"]))
    category = _to_string(_first_value(safe_plan, _FIELD_MAP["category"]))
    brand_key = _to_optional_string(_first_value(safe_plan, _FIELD_MAP["brand_key"]))
    query_terms = _to_string_list(_first_value(safe_plan, _FIELD_MAP["query_terms"]))
    query_tokens = _tokenize_terms(query_terms)

    official_url = _to_string(_first_value(safe_candidate, _FIELD_MAP["candidate_url"]))
    if not official_url:
        official_url = _to_string(_first_value(safe_evidence, _FIELD_MAP["candidate_url"]))

    base_score = _to_int(_first_value(safe_candidate, _FIELD_MAP["candidate_score"]), default=0)

    matched_tokens = _extract_matched_tokens(safe_candidate, safe_evidence)
    matched_bonus = len(matched_tokens) * _WEIGHT_EVIDENCE_MATCHED

    snippet = _to_string(_first_value(safe_evidence, _FIELD_MAP["evidence_body_snippet"]))
    title_text = _extract_title_text(snippet)
    title_token_hits = _match_tokens_in_text(query_tokens, title_text)
    title_bonus = len(title_token_hits) * _WEIGHT_TITLE_TOKEN_HIT

    block_reason = _to_optional_string(_first_value(safe_evidence, _FIELD_MAP["evidence_block_reason"]))
    block_penalty = _PENALTY_BLOCKED if block_reason else 0

    content_type = _to_optional_string(_first_value(safe_evidence, _FIELD_MAP["evidence_content_type"]))
    content_type_lc = content_type.lower() if content_type else ""
    non_html_penalty = _PENALTY_NON_HTML if content_type and "text/html" not in content_type_lc else 0

    snippet_text = snippet.strip()
    short_snippet_penalty = _PENALTY_SHORT_SNIPPET if len(snippet_text) < _SHORT_SNIPPET_THRESHOLD else 0

    total_score = base_score + matched_bonus + title_bonus - block_penalty - non_html_penalty - short_snippet_penalty

    components = {
        "base": base_score,
        "evidence_matched_tokens_bonus": matched_bonus,
        "title_token_hits_bonus": title_bonus,
        "penalty_block": block_penalty,
        "penalty_non_html": non_html_penalty,
        "penalty_short_snippet": short_snippet_penalty,
    }

    reasons: list[str] = [f"base={base_score}"]
    if matched_tokens:
        reasons.append(f"matched_tokens={matched_tokens} (+{matched_bonus})")
    if title_token_hits:
        reasons.append(f"title_token_hits={title_token_hits} (+{title_bonus})")
    if block_penalty:
        reasons.append(f"block_reason={block_reason} (-{block_penalty})")
    if non_html_penalty:
        reasons.append(f"content_type={content_type} (-{non_html_penalty})")
    if short_snippet_penalty:
        reasons.append(f"short_snippet_len={len(snippet_text)} (-{short_snippet_penalty})")
    reasons.append(f"total={total_score}")

    return ScoreBreakdown(
        plan_index=plan_index,
        retail_url=retail_url,
        source=source,
        category=category,
        brand_key=brand_key,
        official_url=official_url,
        total_score=total_score,
        components=components,
        reasons=reasons,
        matched_tokens=matched_tokens,
        title_token_hits=title_token_hits,
        block_reason=block_reason,
        content_type=content_type,
    )


def _first_value(data: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in data:
            return data.get(key)
    return None


def _to_string(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    return ""


def _to_optional_string(value: Any) -> str | None:
    text = _to_string(value)
    return text if text else None


def _to_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            continue
        token = item.strip()
        if not token:
            continue
        lowered = token.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        out.append(token)
    return out


def _to_int(value: Any, *, default: int) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            return int(text)
        except ValueError:
            return default
    return default


def _tokenize_terms(terms: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for term in terms:
        for raw in _TOKEN_SPLIT_RE.split(term.lower()):
            token = raw.strip()
            if not token:
                continue
            if token.isdigit():
                if len(token) < 3:
                    continue
            elif len(token) < 3:
                continue
            if token in seen:
                continue
            seen.add(token)
            out.append(token)
    return out


def _extract_matched_tokens(candidate: dict[str, Any], evidence: dict[str, Any]) -> list[str]:
    evidence_tokens = _to_string_list(_first_value(evidence, _FIELD_MAP["evidence_matched_tokens"]))
    if evidence_tokens:
        return evidence_tokens

    candidate_tokens = _to_string_list(_first_value(candidate, _FIELD_MAP["candidate_matched_tokens"]))
    if candidate_tokens:
        return candidate_tokens

    nested = candidate.get("evidence")
    if isinstance(nested, dict):
        nested_tokens = _to_string_list(nested.get("matched_tokens"))
        if nested_tokens:
            return nested_tokens
    return []


def _extract_title_text(snippet: str) -> str:
    if not snippet:
        return ""
    match = _TITLE_RE.search(snippet)
    if not match:
        return ""
    return _WS_RE.sub(" ", match.group(1)).strip()


def _match_tokens_in_text(tokens: list[str], text: str) -> list[str]:
    if not tokens or not text:
        return []
    lowered = text.lower()
    return [token for token in tokens if token in lowered]
