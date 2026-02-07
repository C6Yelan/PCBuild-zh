# backend/tools/crawler/link_check_json.py
from __future__ import annotations

import argparse
import base64
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse, unquote

import httpx


_TAG_RE = re.compile(r"(?is)<[^>]+>") # 非常粗略的「去 HTML tag」做法，把 <...> 形式的片段當成 tag 移除。
_TITLE_RE = re.compile(r"(?is)<title[^>]*>(?P<t>.*?)</title>") # 抓 <title ...>...</title>，並用命名群組 (?P<t>...) 把內容取出（之後再丟去 _strip_tags() 清理）。
_H1_RE = re.compile(r"(?is)<h1[^>]*>(?P<t>.*?)</h1>") # 抓 <h1 ...>...</h1>；因為很多商品頁面的主標題就在 h1。
# 偏向抓「型號/料號」token：英數 + '-'，長度>=4
_TOKEN_RE = re.compile(r"(?i)[A-Z0-9][A-Z0-9_-]{3,}") # 抓類似「型號/料號」的 token，規則是：英數開頭，長度至少 4（包含開頭），允許中間有 '-'、'_'。
# 強 token：必含數字，允許較短（>=3）以涵蓋 X16、2TB、7200 等，提升 mismatch 檢出
_STRONG_TOKEN_RE = re.compile(r"(?i)(?=[A-Z0-9_-]*\d)[A-Z0-9][A-Z0-9_-]{2,}")
_IBUY_QS_RE = re.compile(r"(?:^|&)iBuy=([^&]+)") # CoolPC evaluate.php?iBuy=... 會把商品標題用 base64 塞在 iBuy 這個 query string 參數裡面。我們用這個 regex 把它抓出來，然後解碼當作比對證據（避免 title/h1 亂碼或不存在的情況）。
_T5NEG_TOKEN_RE = re.compile(r"(?i)T5NEG(?:[_-][A-Z0-9]+)*")
_NON_ALNUM_RE = re.compile(r"[^A-Z0-9]+")
_WEAK_EVIDENCE_RE = re.compile(
    r"(?i)^(?:\d+(?:TB|GB|MB|G|T|M|W|MM|CM|RPM|MHZ|GHZ|GBPS)|\d{2,5}|CL\d+|DDR\d(?:-\d+)?)$"
)
_MATCH_STOPLIST = {
    "INTEL",
    "AMD",
    "NVIDIA",
    "ASUS",
    "MSI",
    "GIGABYTE",
    "PCIE",
    "PCI-E",
    "NVME",
    "SATA",
    "ATX",
    "M-ATX",
    "MATX",
    "ARGB",
    "RGB",
    "CORE",
    "ULTRA",
}

def _coolpc_ibuy_text(url: str) -> str:
    """
    CoolPC evaluate.php?iBuy=... 會把商品標題用 base64 塞在 iBuy。
    我們把它解出來當作比對證據（避免 title/h1 亂碼或不存在）。
    """
    try:
        u = urlparse(url)
        if (u.hostname or "").endswith("coolpc.com.tw") and u.path.endswith("/evaluate.php"):
            m = _IBUY_QS_RE.search(u.query or "")
            if not m:
                return ""
            raw = unquote(m.group(1))  # 用 unquote，避免把 '+' 變空白
            raw = raw.strip()
            raw += "=" * (-len(raw) % 4)  # 補 padding
            b = base64.b64decode(raw, validate=False)
            # CP950/Big5：ASCII token 會原封不動存在，中文也可正常顯示
            for enc in ("cp950", "big5", "utf-8"):
                try:
                    return b.decode(enc)
                except Exception:
                    pass
    except Exception:
        return ""
    return ""


def _load_items(path: Path) -> list[dict[str, Any]]: # 讀入 JSON 或 JSONL 格式的檔案，回傳 dict 的 list。
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    if raw[0] == "[": # JSON array
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError("JSON array expected at top-level.")
        return [x for x in data if isinstance(x, dict)] # 只保留 dict，其他類型的 item 就跳過（比較安全）。
    # JSONL(JSON Lines) fallback
    out: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _strip_tags(s: str) -> str: # 用 regex 粗略「去 tag + 壓空白」，把 <...> 形式的片段當成 tag 移除，然後把多個空白壓成一個，最後 trim。
    s = _TAG_RE.sub(" ", s)
    return " ".join(s.split()).strip()


def _extract_page_title(html: str) -> str: # 從 HTML 內容裡抓 <title> 的內容，然後丟去 _strip_tags() 清理掉可能的 tag。
    m = _TITLE_RE.search(html)
    if m:
        return _strip_tags(m.group("t"))
    return ""


def _extract_h1(html: str) -> str: # 從 HTML 內容裡抓 <h1> 的內容，然後丟去 _strip_tags() 清理掉可能的 tag。
    m = _H1_RE.search(html)
    if m:
        return _strip_tags(m.group("t"))
    return ""


def _tokenize(s: str) -> list[str]: # 把字串裡的「型號/料號」token 抓出來，回傳大寫的 token list，去重但保序。
    if not s:
        return []
    toks = [t.upper() for t in _TOKEN_RE.findall(s)] # 抓出所有符合規則的 token，並轉成大寫。
    seen: set[str] = set() # 去重但保序：用 seen set 記錄已經見過的 token，然後只把第一次見到的 token 加到 out list 裡。
    out: list[str] = []
    for t in toks:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out

def _tokenize_strong(s: str) -> list[str]:
    """強 token：必含數字、允許短一點（>=3），用於優先命中判定。"""
    if not s:
        return []
    toks = [t.upper() for t in _STRONG_TOKEN_RE.findall(s)]
    seen: set[str] = set()
    out: list[str] = []
    for t in toks:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out

def _dedup_preserve(seq: Iterable[str]) -> list[str]:
    """簡單的去重但保序工具，給定一個字串序列，回傳一個新的 list，其中包含原序列中第一次出現的每個唯一字串。"""
    seen: set[str] = set()
    out: list[str] = []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _extract_t5neg_tokens(s: str) -> list[str]:
    """抓出 sanity v2 注入 token（例如 T5NEG_XXXX），僅在出現時啟用 must-match 規則。"""
    if not s:
        return []
    return _dedup_preserve(t.upper() for t in _T5NEG_TOKEN_RE.findall(s))


def _is_weak_evidence_token(token: str) -> bool:
    """容量/規格數字 token（2TB/650W/2280/CL40 等）屬於弱證據，不能單獨判 match。"""
    return bool(_WEAK_EVIDENCE_RE.fullmatch(token))


def _is_high_signal_token(token: str) -> bool:
    """
    高信號 token：長度 >= 4、含數字且含字母，並排除 stoplist/弱證據。
    通常對應型號/料號（如 W680M-ACE、A650GLS）。
    """
    if len(token) < 4:
        return False
    if token in _MATCH_STOPLIST:
        return False
    if _is_weak_evidence_token(token):
        return False
    has_digit = any(ch.isdigit() for ch in token)
    has_alpha = any("A" <= ch <= "Z" for ch in token)
    return has_digit and has_alpha


def _normalize_token(token: str) -> str:
    """把 token 正規化為純英數，用於處理 '-'/'_' 等符號差異。"""
    return _NON_ALNUM_RE.sub("", token.upper())


def _collect_evidence_tokens(haystack: str) -> list[str]:
    """對 haystack 也做 tokenization，改用 token set 交集做命中判定。"""
    return _dedup_preserve(_tokenize_strong(haystack) + _tokenize(haystack))


def _token_hits_evidence(
    token: str,
    evidence_set: set[str],
    evidence_norm_set: set[str],
) -> bool:
    if token in evidence_set:
        return True
    norm = _normalize_token(token)
    if len(norm) >= 4 and norm in evidence_norm_set:
        return True
    return False


def _domain_allowed(url: str, allow_domains: list[str]) -> bool: 
    """判斷 URL 的網域是否在允許清單裡，allow_domains 是允許的網域列表。如果 allow_domains 是空的，就表示不限制網域，全部允許。"""
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
    redirect_chain: list[str] # 中繼 URL 列表，不包含原始 URL，但包含最終 URL（如果有重定向的話）。如果沒有重定向，則為空列表。
    page_title: str
    h1: str
    basis: str
    tokens: list[str]
    matched_tokens: list[str]
    filtered_tokens: list[str]
    stopword_hits: list[str]
    must_match_tokens: list[str]
    missing_must_match_tokens: list[str]
    reason: str


def _fetch_final_and_snippet( # 追到最終 URL、保留 redirect chain、並只抓固定大小的 HTML 片段（避免抓整頁造成資源浪費）。
    client: httpx.Client,
    url: str,
    max_bytes: int,
) -> tuple[int, str, list[str], str]:
    """
    returns: 
    (status_code: 最後一次回應的 HTTP 狀態碼,
      final_url: 跟隨 redirect 後的最終落地 URL, 
      redirect_chain: redirect 過程中的歷史 URL 列表（證據鏈）,
      html_snippet: 只讀取前 max_bytes 的 HTML 片段（通常足夠抓 <title>/<h1>）
    """
    with client.stream("GET", url) as r:
        chunks: list[bytes] = []
        total = 0
        for b in r.iter_bytes():
            if not b:
                break
            chunks.append(b)
            total += len(b)
            if total >= max_bytes: # 只抓關鍵資訊所需的前 max_bytes bytes，避免抓整頁造成資源浪費。
                break
        snippet = b"".join(chunks).decode("utf-8", errors="ignore")
        chain = [str(x.url) for x in (r.history or [])] # 原始 URL → 中繼跳轉 → 最終落地 URL 的證據鏈
        return r.status_code, str(r.url), chain, snippet


def _check_one( # 單筆連結檢查：欄位抽取 → 網域/缺值檢查 → 抓頁面訊號 → token 命中判定 → 回傳 match/mismatch/error 結果。
    client: httpx.Client,
    item: dict[str, Any],
    allow_domains: list[str],
    max_bytes: int,
) -> LinkCheckResult:
    url = str(item.get("url") or "")
    title = str(item.get("title") or "")
    sku_hint = str(item.get("sku_hint") or "")

    if not url: # 沒有 URL 就沒得檢查，直接回 error。
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
            filtered_tokens=[],
            stopword_hits=[],
            must_match_tokens=[],
            missing_must_match_tokens=[],
            reason="missing_url",
        )

    if not _domain_allowed(url, allow_domains): # 網域不在允許清單裡，直接回 error。
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
            filtered_tokens=[],
            stopword_hits=[],
            must_match_tokens=[],
            missing_must_match_tokens=[],
            reason="domain_not_allowed",
        )

    try: # 嘗試抓取最終 URL、redirect chain、以及 HTML 片段（包含 <title> 和 <h1> 等關鍵訊號）。如果抓取過程中發生任何例外，就回 error。
        http_status, final_url, chain, snippet = _fetch_final_and_snippet(
            client, url, max_bytes=max_bytes
        )
        page_title = _extract_page_title(snippet)
        h1 = _extract_h1(snippet)
        ibuy_text = _coolpc_ibuy_text(final_url)
        haystack = f"{final_url} {page_title} {h1} {ibuy_text}".upper()

        # token 來源：sku_hint + title union（避免像 HDD 這種 sku_hint 太硬導致正樣本 mismatch）
        basis = "sku_hint+title"
        key_text = f"{sku_hint} {title}".strip()
        must_match_tokens = _extract_t5neg_tokens(key_text)
        strong_tokens = _tokenize_strong(key_text)
        tokens = _dedup_preserve(must_match_tokens + strong_tokens + _tokenize(key_text))
        evidence_tokens = _collect_evidence_tokens(haystack)
        evidence_set = set(evidence_tokens)
        evidence_norm_set = {_normalize_token(t) for t in evidence_tokens if _normalize_token(t)}
        matched_tokens = [
            t for t in tokens if _token_hits_evidence(t, evidence_set, evidence_norm_set)
        ]
        stopword_hits = [t for t in matched_tokens if t in _MATCH_STOPLIST]
        filtered_tokens = [
            t for t in matched_tokens if t not in _MATCH_STOPLIST and not _is_weak_evidence_token(t)
        ]
        weak_support_hits = [
            t for t in matched_tokens if t not in _MATCH_STOPLIST and _is_weak_evidence_token(t)
        ]
        high_signal_hits = [t for t in filtered_tokens if _is_high_signal_token(t)]
        missing_must_match_tokens = [
            t for t in must_match_tokens if not _token_hits_evidence(t, evidence_set, evidence_norm_set)
        ]

        # sanity v2 專用：只有出現 T5NEG token 時，才啟用 must-match 規則。
        if missing_must_match_tokens:
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
                matched_tokens=matched_tokens[:10],
                filtered_tokens=filtered_tokens[:10],
                stopword_hits=stopword_hits[:10],
                must_match_tokens=must_match_tokens[:10],
                missing_must_match_tokens=missing_must_match_tokens[:10],
                reason="missing_must_match_token",
            )

        # 一般判定：
        # 1) 至少命中 1 個高信號 token（長度 >=4 且含數字、非 stoplist/弱證據）
        # 2) 否則至少命中 2 個非 stoplist 的中等 token
        # 3) 為避免誤殺，允許 1 個中等 token + 1 個弱 token 的組合（弱 token 仍不能單獨成立）
        if tokens and (
            high_signal_hits
            or len(filtered_tokens) >= 2
            or (len(filtered_tokens) >= 1 and len(weak_support_hits) >= 1)
        ):
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
                matched_tokens=matched_tokens[:10],
                filtered_tokens=filtered_tokens[:10],
                stopword_hits=stopword_hits[:10],
                must_match_tokens=must_match_tokens[:10],
                missing_must_match_tokens=[],
                reason=(
                    "high_signal_token_hit>=1"
                    if high_signal_hits
                    else "filtered_token_hit>=2"
                    if len(filtered_tokens) >= 2
                    else "filtered_token_hit>=1_and_weak_support>=1"
                ),
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
            matched_tokens=matched_tokens[:10],
            filtered_tokens=filtered_tokens[:10],
            stopword_hits=stopword_hits[:10],
            must_match_tokens=must_match_tokens[:10],
            missing_must_match_tokens=[],
            reason="insufficient_filtered_token_hit",
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
            filtered_tokens=[],
            stopword_hits=[],
            must_match_tokens=[],
            missing_must_match_tokens=[],
            reason=f"fetch_error:{type(e).__name__}",
        )


def main(argv: list[str] | None = None) -> int: # 主程式：CLI 參數 → 讀入 items → 建立 HTTP client → 逐筆檢查 → 輸出 report/quarantine/summary
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
                "filtered_tokens": res.filtered_tokens,
                "stopword_hits": res.stopword_hits,
                "must_match_tokens": res.must_match_tokens,
                "missing_must_match_tokens": res.missing_must_match_tokens,
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
