# backend/tools/crawler/link_check_json.py
from __future__ import annotations

import argparse
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

import httpx


_TAG_RE = re.compile(r"(?is)<[^>]+>")
_TITLE_RE = re.compile(r"(?is)<title[^>]*>(?P<t>.*?)</title>")
_H1_RE = re.compile(r"(?is)<h1[^>]*>(?P<t>.*?)</h1>")
# 偏向抓「型號/料號」token：英數 + '-'，長度>=4
_TOKEN_RE = re.compile(r"(?i)[A-Z0-9][A-Z0-9-]{3,}")


def _load_items(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    if raw[0] == "[":
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError("JSON array expected at top-level.")
        return [x for x in data if isinstance(x, dict)]
    # JSONL fallback
    out: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _strip_tags(s: str) -> str:
    s = _TAG_RE.sub(" ", s)
    return " ".join(s.split()).strip()


def _extract_page_title(html: str) -> str:
    m = _TITLE_RE.search(html)
    if m:
        return _strip_tags(m.group("t"))
    return ""


def _extract_h1(html: str) -> str:
    m = _H1_RE.search(html)
    if m:
        return _strip_tags(m.group("t"))
    return ""


def _tokenize(s: str) -> list[str]:
    if not s:
        return []
    toks = [t.upper() for t in _TOKEN_RE.findall(s)]
    # 去重但保序
    seen: set[str] = set()
    out: list[str] = []
    for t in toks:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _domain_allowed(url: str, allow_domains: list[str]) -> bool:
    if not allow_domains:
        return True
    host = (urlparse(url).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in allow_domains)


@dataclass
class LinkCheckResult:
    status: str  # match|mismatch|error
    http_status: int | None
    url: str
    final_url: str | None
    redirect_chain: list[str]
    page_title: str
    h1: str
    basis: str
    tokens: list[str]
    matched_tokens: list[str]
    reason: str


def _fetch_final_and_snippet(
    client: httpx.Client,
    url: str,
    max_bytes: int,
) -> tuple[int, str, list[str], str]:
    """
    returns: (status_code, final_url, redirect_chain, html_snippet)
    """
    with client.stream("GET", url) as r:
        chunks: list[bytes] = []
        total = 0
        for b in r.iter_bytes():
            if not b:
                break
            chunks.append(b)
            total += len(b)
            if total >= max_bytes:
                break
        snippet = b"".join(chunks).decode("utf-8", errors="ignore")
        chain = [str(x.url) for x in (r.history or [])]
        return r.status_code, str(r.url), chain, snippet


def _check_one(
    client: httpx.Client,
    item: dict[str, Any],
    allow_domains: list[str],
    max_bytes: int,
) -> LinkCheckResult:
    url = str(item.get("url") or "")
    title = str(item.get("title") or "")
    sku_hint = str(item.get("sku_hint") or "")

    if not url:
        return LinkCheckResult(
            status="error",
            http_status=None,
            url=url,
            final_url=None,
            redirect_chain=[],
            page_title="",
            h1="",
            basis="",
            tokens=[],
            matched_tokens=[],
            reason="missing_url",
        )

    if not _domain_allowed(url, allow_domains):
        return LinkCheckResult(
            status="error",
            http_status=None,
            url=url,
            final_url=None,
            redirect_chain=[],
            page_title="",
            h1="",
            basis="",
            tokens=[],
            matched_tokens=[],
            reason="domain_not_allowed",
        )

    try:
        http_status, final_url, chain, snippet = _fetch_final_and_snippet(
            client, url, max_bytes=max_bytes
        )
        page_title = _extract_page_title(snippet)
        h1 = _extract_h1(snippet)
        haystack = f"{final_url} {page_title} {h1}".upper()

        # 優先用 sku_hint token（你前面已經花很多力氣把 sku_hint 做準）
        basis = "sku_hint" if sku_hint.strip() else "title"
        tokens = _tokenize(sku_hint if basis == "sku_hint" else title)

        matched = [t for t in tokens if t and t in haystack]

        # 判定規則（先保守）：至少命中 1 個 token 才算 match
        # 沒命中 -> mismatch（高風險，進隔離）
        if tokens and matched:
            return LinkCheckResult(
                status="match",
                http_status=http_status,
                url=url,
                final_url=final_url,
                redirect_chain=chain,
                page_title=page_title,
                h1=h1,
                basis=basis,
                tokens=tokens,
                matched_tokens=matched[:10],
                reason="token_hit>=1",
            )

        return LinkCheckResult(
            status="mismatch",
            http_status=http_status,
            url=url,
            final_url=final_url,
            redirect_chain=chain,
            page_title=page_title,
            h1=h1,
            basis=basis,
            tokens=tokens,
            matched_tokens=[],
            reason="no_token_hit",
        )

    except Exception as e:
        return LinkCheckResult(
            status="error",
            http_status=None,
            url=url,
            final_url=None,
            redirect_chain=[],
            page_title="",
            h1="",
            basis="",
            tokens=[],
            matched_tokens=[],
            reason=f"fetch_error:{type(e).__name__}",
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Path to parsed JSON (array or JSONL)")
    ap.add_argument("--out-dir", required=True, help="Output directory")
    ap.add_argument("--allow-domain", action="append", default=[], help="Allowlist domain suffix, e.g. coolpc.com.tw")
    ap.add_argument("--max-items", type=int, default=0, help="0 means all items")
    ap.add_argument("--sleep-ms", type=int, default=150, help="Politeness delay between requests")
    ap.add_argument("--timeout-s", type=float, default=12.0)
    ap.add_argument("--max-bytes", type=int, default=120_000, help="Max bytes to read from final page")
    args = ap.parse_args(argv)

    in_path = Path(args.input)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    items = _load_items(in_path)
    if args.max_items and args.max_items > 0:
        items = items[: args.max_items]

    report_path = out_dir / "link_check_report.jsonl"
    quarantine_path = out_dir / "link_check_quarantine.jsonl"
    summary_path = out_dir / "link_check_summary.json"

    # 安全/可預期：不吃環境 proxy；TLS verify 保持預設 True
    # httpx 需顯式 follow_redirects=True 才會追到最終 URL。:contentReference[oaicite:4]{index=4}
    client = httpx.Client(
        follow_redirects=True,
        timeout=httpx.Timeout(args.timeout_s),
        headers={"User-Agent": "PCBuild-zh LinkCheck/1.0"},
        trust_env=False,
    )

    counts = {"match": 0, "mismatch": 0, "error": 0, "total": 0}

    with report_path.open("w", encoding="utf-8") as rf, quarantine_path.open(
        "w", encoding="utf-8"
    ) as qf:
        for it in items:
            res = _check_one(client, it, args.allow_domain, args.max_bytes)
            counts["total"] += 1
            counts[res.status] += 1

            obj = {
                "status": res.status,
                "http_status": res.http_status,
                "url": res.url,
                "final_url": res.final_url,
                "redirect_chain": res.redirect_chain,
                "page_title": res.page_title,
                "h1": res.h1,
                "basis": res.basis,
                "tokens": res.tokens,
                "matched_tokens": res.matched_tokens,
                "reason": res.reason,
                "category": it.get("category"),
                "title": it.get("title"),
                "sku_hint": it.get("sku_hint"),
            }
            rf.write(json.dumps(obj, ensure_ascii=False) + "\n")

            if res.status != "match":
                # mismatch/error：直接進隔離（不入庫）
                q_obj = dict(it)
                q_obj["link_check"] = obj
                qf.write(json.dumps(q_obj, ensure_ascii=False) + "\n")

            time.sleep(max(args.sleep_ms, 0) / 1000.0)

    client.close()

    summary_path.write_text(json.dumps(counts, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(counts, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
