# backend/services/crawler/link_consistency_gate/engine.py
# crawler pipeline 的「連結一致性品質閘門執行器」：把每筆商品連結檢查流程標準化、可落檔、可隔離（quarantine），確保下游入庫與 AI 配單不會吃到錯頁/被擋頁/偏移連結。
from __future__ import annotations

import base64
import re
import time
from typing import Any
from urllib.parse import unquote, urlparse

import httpx

from . import extract, registry
from .fetch import Fetcher
from .types import BlockDetectionConfig, EngineConfig, LinkCheckReport, ListingInput, PageSignals


class LinkCheckEngine: # 建立http客戶端、Fetcher、阻擋頁面規則。
    def __init__(self, config: EngineConfig) -> None:
        self._config = config
        self._client = httpx.Client(follow_redirects=False, timeout=httpx.Timeout(config.fetch.timeout_s)) # 建立http客戶端，設定不跟隨重定向、設定超時。
        self._fetcher = Fetcher(self._client, fetch=config.fetch, pacing=config.pacing) # 建立Fetcher，傳入http客戶端、fetch設定、pacing設定。
        self._block_regexes = _compile_block_patterns(config.block) # 編譯阻擋頁面規則的正則表達式。

    def close(self) -> None: # 關閉http客戶端。
        self._client.close()

    def __enter__(self) -> "LinkCheckEngine": # 支持with語句，返回自己。
        return self

    def __exit__(self, exc_type, exc, tb) -> None: # 支持with語句，退出時關閉http客戶端。
        self.close()

    def check_one(self, listing: ListingInput) -> LinkCheckReport: # 檢查單個鏈接，返回檢查報告。
        start = time.monotonic()

        decoded_text = _coolpc_try_decode_ibuy(listing.url)
        if decoded_text:
            final_url = listing.url
            http_status = 200
            fetch_meta = self._fetcher.pop_last_meta()
            signals = PageSignals(
                final_url=final_url,
                http_status=http_status,
                page_title=None,
                page_h1=None,
                canonical_url=None,
                text_hint=decoded_text,
            )
        else:
            try: # 使用Fetcher獲取鏈接內容，獲取最終URL、HTTP狀態碼、內容字節和fetch元數據。如果獲取過程中發生異常，返回包含錯誤信息的LinkCheckReport。
                final_url, http_status, content_bytes, _fetch_elapsed_ms = self._fetcher.fetch(listing.url)
                fetch_meta = self._fetcher.pop_last_meta()
            except Exception as e:
                elapsed_ms = int((time.monotonic() - start) * 1000)
                return LinkCheckReport(
                    source=listing.source,
                    category=listing.category,
                    title=listing.title,
                    url=listing.url,
                    final_url="",
                    status="error",
                    http_status=None,
                    elapsed_ms=elapsed_ms,
                    reason_code="FETCH_ERROR",
                    evidence={
                        "listing_tokens": [],
                        "page_tokens": [],
                        "matched_tokens": [],
                        "notes": ["fetch failed"],
                    },
                    error={"type": type(e).__name__, "message": _one_line(str(e), max_len=240)},
                )

            # Block/interstitial detection (even when HTTP 200).
            if self._block_regexes:
                normalized = extract.html_to_text(content_bytes, max_chars=20000)
                matched = [rx.pattern for rx in self._block_regexes if rx.search(normalized)]
                if matched:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    evidence: dict[str, Any] = {
                        "listing_tokens": [],
                        "page_tokens": [],
                        "matched_tokens": [],
                        "notes": ["block/interstitial page detected"],
                        "block_patterns": matched,
                        "fetch_warnings": fetch_meta.warnings,
                        "redirect_chain": fetch_meta.redirect_chain,
                    }
                    return LinkCheckReport(
                        source=listing.source,
                        category=listing.category,
                        title=listing.title,
                        url=listing.url,
                        final_url=final_url,
                        status="error",
                        http_status=http_status,
                        elapsed_ms=elapsed_ms,
                        reason_code="BLOCK_PAGE_DETECTED",
                        evidence=evidence,
                        error={"type": "BlockedByInterstitial", "message": "block/interstitial page detected"},
                    )

            try: # 提取頁面信號，傳入內容字節、最終URL和HTTP狀態碼。如果提取過程中發生異常，返回包含錯誤信息的LinkCheckReport。
                signals = extract.extract_page_signals(
                    content_bytes,
                    final_url=final_url,
                    http_status=http_status,
                )
            except Exception as e:
                elapsed_ms = int((time.monotonic() - start) * 1000)
                return LinkCheckReport(
                    source=listing.source,
                    category=listing.category,
                    title=listing.title,
                    url=listing.url,
                    final_url=final_url,
                    status="error",
                    http_status=http_status,
                    elapsed_ms=elapsed_ms,
                    reason_code="EXTRACT_ERROR",
                    evidence={
                        "listing_tokens": [],
                        "page_tokens": [],
                        "matched_tokens": [],
                        "notes": ["extract failed"],
                        "fetch_warnings": fetch_meta.warnings,
                        "redirect_chain": fetch_meta.redirect_chain,
                    },
                    error={"type": type(e).__name__, "message": _one_line(str(e), max_len=240)},
                )

        strategy = registry.get_strategy(listing.category)
        try: # 使用策略決策，傳入listing和提取的信號。如果策略過程中發生異常，返回包含錯誤信息的LinkCheckReport。
            decision = strategy.decide(listing, signals)
        except Exception as e:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return LinkCheckReport(
                source=listing.source,
                category=listing.category,
                title=listing.title,
                url=listing.url,
                final_url=final_url,
                status="error",
                http_status=http_status,
                elapsed_ms=elapsed_ms,
                reason_code="STRATEGY_ERROR",
                evidence={
                    "listing_tokens": [],
                    "page_tokens": [],
                    "matched_tokens": [],
                    "notes": ["strategy failed"],
                    "fetch_warnings": fetch_meta.warnings,
                    "redirect_chain": fetch_meta.redirect_chain,
                },
                error={"type": type(e).__name__, "message": _one_line(str(e), max_len=240)},
            )

        evidence = dict(decision.evidence or {})
        evidence.setdefault("listing_tokens", [])
        evidence.setdefault("page_tokens", [])
        evidence.setdefault("matched_tokens", [])
        evidence.setdefault("notes", [])

        if fetch_meta.warnings:
            evidence["fetch_warnings"] = fetch_meta.warnings
        if fetch_meta.redirect_chain:
            evidence["redirect_chain"] = fetch_meta.redirect_chain

        elapsed_ms = int((time.monotonic() - start) * 1000)
        return LinkCheckReport(
            source=listing.source,
            category=listing.category,
            title=listing.title,
            url=listing.url,
            final_url=signals.final_url,
            status=decision.status,
            http_status=signals.http_status,
            elapsed_ms=elapsed_ms,
            reason_code=decision.reason_code,
            evidence=evidence,
            error=None,
        )


def _compile_block_patterns(cfg: BlockDetectionConfig) -> list[re.Pattern[str]]: 
    # 編譯阻擋頁面規則的正則表達式。如果配置未啟用，返回空列表。否則，對每個模式進行編譯，如果編譯失敗則引發ValueError異常。
    if not cfg.enabled:
        return []
    regexes: list[re.Pattern[str]] = []
    for p in cfg.patterns:
        try:
            regexes.append(re.compile(p, flags=re.IGNORECASE))
        except re.error as e:
            raise ValueError(f"invalid block pattern regex: {p!r}: {e}") from e
    return regexes


_RE_WS = re.compile(r"\s+", flags=re.UNICODE)


def _one_line(s: str, *, max_len: int) -> str:
    s = _RE_WS.sub(" ", s or "").strip()
    if len(s) > max_len:
        s = s[: max_len - 3] + "..."
    return s


def _extract_raw_query_param(query: str, key: str) -> str | None:
    # Avoid parse_qs/unquote_plus: '+' must remain '+' for base64.
    if not query or not key:
        return None
    rx = re.compile(rf"(?:^|&){re.escape(key)}=([^&]+)", flags=re.UNICODE)
    m = rx.search(query)
    if not m:
        return None
    val = m.group(1)
    if not val:
        return None
    return val


def _coolpc_try_decode_ibuy(url: str) -> str | None:
    """
    CoolPC evaluate.php encodes product text in `iBuy` (base64).
    Prefer decoding it directly to avoid fetching large/Big5 HTML.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return None

    host = (parsed.hostname or "").lower()
    if host != "www.coolpc.com.tw":
        return None
    if (parsed.path or "") != "/evaluate.php":
        return None

    raw_ibuy = _extract_raw_query_param(parsed.query or "", "iBuy")
    if not raw_ibuy:
        return None

    # NOTE: use unquote (not unquote_plus) to preserve '+'.
    ibuy = unquote(raw_ibuy)
    if not ibuy:
        return None

    pad_len = (-len(ibuy)) % 4
    if pad_len:
        ibuy += "=" * pad_len

    try:
        decoded_bytes = base64.b64decode(ibuy, validate=True)
    except Exception:
        return None

    if not decoded_bytes:
        return None

    text = decoded_bytes.decode("big5", errors="replace")
    if not text.strip():
        text = decoded_bytes.decode("utf-8", errors="replace")
    if not text.strip():
        return None
    return text
