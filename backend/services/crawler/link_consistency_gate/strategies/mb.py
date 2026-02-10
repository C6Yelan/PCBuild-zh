from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..types import ListingInput, MatchDecision, PageSignals


_RE_WS = re.compile(r"\s+", flags=re.UNICODE)
_RE_BRACKET_SQ = re.compile(r"【[^】]*】", flags=re.UNICODE)
_RE_BRACKET_PAREN = re.compile(r"\([^)]*\)", flags=re.UNICODE)
_RE_BRACKET_PAREN_FULL = re.compile(r"（[^）]*）", flags=re.UNICODE)
_RE_SEP = re.compile(r"[\\/._-]+", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[a-z0-9]+", flags=re.UNICODE)

# Keep this list intentionally small; only used when we have to fall back to listing.title.
_TITLE_BRAND_PREFIXES = (
    "ASUS",
    "華碩",
    "MSI",
    "微星",
    "GIGABYTE",
    "技嘉",
    "ASROCK",
    "華擎",
)


def _strip_brackets(s: str) -> str:
    s = _RE_BRACKET_SQ.sub(" ", s)
    s = _RE_BRACKET_PAREN.sub(" ", s)
    s = _RE_BRACKET_PAREN_FULL.sub(" ", s)
    return s


def _normalize(s: str) -> str:
    s = (s or "").replace("\u3000", " ").replace("\xa0", " ")
    s = s.lower()
    s = _strip_brackets(s)
    s = _RE_SEP.sub(" ", s)
    s = _RE_WS.sub(" ", s).strip()
    return s


def _strip_title_brand_prefix(title: str) -> str:
    s = (title or "").strip()
    if not s:
        return s
    s_lower = s.lower()
    for p in _TITLE_BRAND_PREFIXES:
        pl = p.lower()
        if s_lower.startswith(pl):
            s = s[len(p) :].lstrip(" :-_/|")
            break
    return s


def _pick_model_phrase(listing: ListingInput) -> tuple[str, str]:
    mh = listing.extra.get("model_hint")
    if isinstance(mh, str) and mh.strip():
        return mh, "extra.model_hint"
    if (listing.sku_hint or "").strip():
        return listing.sku_hint, "sku_hint"
    return _strip_title_brand_prefix(listing.title), "title"


def _build_page_text(signals: PageSignals) -> str:
    parts: list[str] = []
    for s in (signals.page_title, signals.page_h1, signals.text_hint):
        if s:
            parts.append(s)
    return _normalize(" ".join(parts))


def _tokenize(text_norm: str) -> list[str]:
    """
    Tokenize from normalized text (separators collapsed to spaces).
    - base tokens: [a-z0-9]+
    - derived compound tokens: join a strong base token with following tokens using '-'
      to cover forms like H610M-ITX / H81M-K even when page uses whitespace separators.
    """
    base = [t for t in _RE_TOKEN.findall(text_norm or "") if t]
    out: set[str] = set(base)

    for i in range(len(base) - 1):
        a = base[i]
        b = base[i + 1]
        if _is_strong_token(a) and b:
            out.add(f"{a}-{b}")
            if i + 2 < len(base):
                c = base[i + 2]
                if c:
                    out.add(f"{a}-{b}-{c}")

    return sorted(out)


def _is_strong_token(tok: str) -> bool:
    if not tok or len(tok) < 4:
        return False
    has_alpha = any("a" <= ch <= "z" for ch in tok)
    has_digit = any("0" <= ch <= "9" for ch in tok)
    return has_alpha and has_digit


def _select_strong_tokens(tokens: list[str]) -> set[str]:
    strong = {t for t in tokens if _is_strong_token(t)}
    compound = {t for t in strong if "-" in t}
    simple = {t for t in strong if "-" not in t}
    # Prefer specificity: if we have compound strong tokens, drop simple tokens that are just the base prefix.
    filtered_simple = {t for t in simple if not any(c.startswith(f"{t}-") for c in compound)}
    return filtered_simple | compound


@dataclass(frozen=True)
class MbStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_phrase_raw, model_src = _pick_model_phrase(listing)
        model_phrase_norm = _normalize(model_phrase_raw)

        page_text = _build_page_text(signals)
        if not page_text:
            listing_tokens = _tokenize(model_phrase_norm)
            evidence: dict[str, Any] = {
                "listing_tokens": listing_tokens,
                "page_tokens": [],
                "matched_tokens": [],
                "notes": [
                    "page_text is empty (page_title/page_h1/text_hint all missing or blank)",
                    f"model_source={model_src}",
                ],
            }
            return MatchDecision(status="uncertain", score=None, reason_code="PAGE_TEXT_EMPTY", evidence=evidence)

        listing_tokens = _tokenize(model_phrase_norm)
        page_tokens = _tokenize(page_text)
        matched_tokens = sorted(set(listing_tokens) & set(page_tokens))

        if not model_phrase_norm:
            evidence = {
                "listing_tokens": listing_tokens,
                "page_tokens": page_tokens,
                "matched_tokens": matched_tokens,
                "notes": ["model_phrase is empty after normalization", f"model_source={model_src}"],
            }
            return MatchDecision(status="uncertain", score=None, reason_code="MODEL_EMPTY", evidence=evidence)

        if model_phrase_norm in page_text:
            evidence = {
                "listing_tokens": listing_tokens,
                "page_tokens": page_tokens,
                "matched_tokens": matched_tokens,
                "notes": [
                    "phrase match via normalized substring",
                    f"model_source={model_src}",
                ],
            }
            return MatchDecision(status="match", score=None, reason_code="MODEL_PHRASE_FOUND", evidence=evidence)

        listing_strong = _select_strong_tokens(listing_tokens)
        page_strong = _select_strong_tokens(page_tokens)
        matched_strong = sorted(listing_strong & page_strong)

        if listing_strong and page_strong and matched_strong:
            evidence = {
                "listing_tokens": listing_tokens,
                "page_tokens": page_tokens,
                "matched_tokens": matched_tokens,
                "notes": [
                    "token match via strong token intersection",
                    f"strong_tokens(listing/page)={len(listing_strong)}/{len(page_strong)}",
                ],
            }
            return MatchDecision(status="match", score=None, reason_code="MODEL_TOKEN_MATCH", evidence=evidence)

        if listing_strong and not matched_strong:
            evidence = {
                "listing_tokens": listing_tokens,
                "page_tokens": page_tokens,
                "matched_tokens": matched_tokens,
                "notes": [
                    "listing has strong token(s) but none matched in page_text",
                    f"strong_tokens(listing/page)={len(listing_strong)}/{len(page_strong)}",
                ],
            }
            return MatchDecision(status="mismatch", score=None, reason_code="MODEL_TOKEN_MISSING", evidence=evidence)

        evidence = {
            "listing_tokens": listing_tokens,
            "page_tokens": page_tokens,
            "matched_tokens": matched_tokens,
            "notes": [
                "insufficient strong tokens for a confident decision",
                f"strong_tokens(listing/page)={len(listing_strong)}/{len(page_strong)}",
            ],
        }
        return MatchDecision(status="uncertain", score=None, reason_code="TOKEN_WEAK_OR_EMPTY", evidence=evidence)

