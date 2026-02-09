# backend/tools/crawler/link_check_json.py
from __future__ import annotations

import argparse
import base64
import json
import os
import random
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Iterable, Literal
from urllib.parse import urlparse, unquote

try:
    import httpx
except ModuleNotFoundError:  # pragma: no cover
    # Allow `-h` / `compileall` / simulate-only runs to work in minimal environments.
    httpx = None  # type: ignore[assignment]


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
_DEFAULT_WEAK_EVIDENCE_RE = re.compile(
    r"(?i)^(?:\d+(?:TB|GB|MB|G|T|M|W|MM|CM|RPM|MHZ|GHZ|GBPS)|\d{2,5}|CL\d+|DDR\d(?:-\d+)?)$"
)

MatchPolicy = Literal["strict", "default"]
DEFAULT_BLOCK_PATTERNS = (
    "辛苦了，喝杯咖啡休息一下",
    "辛苦了,喝杯咖啡休息一下",
    "喝杯咖啡休息一下",
    "聯絡我們的管理員吧",
)
DEFAULT_BLOCK_ENCODINGS = ("utf-8", "cp950", "big5")


@dataclass
class RuleProfile:
    profile_id: str
    stoplist: set[str]
    weak_evidence_re: re.Pattern[str]
    min_high_signal_len: int
    allow_alpha_only_brand_match: bool
    # Some categories (e.g. CASE_FAN accessories) may only have a single alpha-only model token.
    # Keep this disabled by default; enable per-category with a conservative denylist.
    allow_alpha_only_model_match: bool = False
    alpha_only_model_min_len: int = 5
    alpha_only_model_denylist: frozenset[str] = frozenset()
    match_policy: MatchPolicy = "default"


@dataclass
class CrawlPolicy:
    sleep_min_ms: int
    sleep_max_ms: int
    gap_min_ms: int
    gap_max_ms: int
    cooldown_base_s: float
    cooldown_max_s: float
    block_max_retries: int
    max_total_cooldown_s: float
    block_patterns: tuple[str, ...]
    block_encodings: tuple[str, ...]
    block_domains: tuple[str, ...]
    simulate_block_every: int = 0
    simulate_block_encoding: str = "utf-8"


DEFAULT_PROFILE = RuleProfile(
    profile_id="default",
    stoplist={
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
    },
    weak_evidence_re=_DEFAULT_WEAK_EVIDENCE_RE,
    min_high_signal_len=4,
    allow_alpha_only_brand_match=False,
    allow_alpha_only_model_match=False,
    alpha_only_model_min_len=5,
    alpha_only_model_denylist=frozenset(),
    match_policy="default",
)


# 先示範 category 覆寫框架；目前值刻意與 DEFAULT 一致，避免重構時改變既有行為。
RULES_BY_CATEGORY: dict[str, RuleProfile] = {
    "CASE": RuleProfile(
        profile_id="case_default",
        stoplist=set(DEFAULT_PROFILE.stoplist),
        weak_evidence_re=DEFAULT_PROFILE.weak_evidence_re,
        min_high_signal_len=DEFAULT_PROFILE.min_high_signal_len,
        allow_alpha_only_brand_match=False,
        allow_alpha_only_model_match=False,
        alpha_only_model_min_len=DEFAULT_PROFILE.alpha_only_model_min_len,
        alpha_only_model_denylist=frozenset(),
        match_policy=DEFAULT_PROFILE.match_policy,
    ),
    "CASE_FAN": RuleProfile(
        profile_id="case_fan_default",
        stoplist=set(DEFAULT_PROFILE.stoplist),
        weak_evidence_re=DEFAULT_PROFILE.weak_evidence_re,
        min_high_signal_len=DEFAULT_PROFILE.min_high_signal_len,
        allow_alpha_only_brand_match=False,
        allow_alpha_only_model_match=False,
        alpha_only_model_min_len=DEFAULT_PROFILE.alpha_only_model_min_len,
        alpha_only_model_denylist=frozenset(),
        match_policy=DEFAULT_PROFILE.match_policy,
    ),
}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw.strip())
    except ValueError:
        return default


def _env_list(name: str) -> list[str]:
    raw = os.getenv(name)
    if raw is None:
        return []
    s = raw.strip()
    if not s:
        return []
    if "||" in s:
        parts = [x.strip() for x in s.split("||")]
    else:
        parts = [x.strip() for x in s.split(",")]
    return [x for x in parts if x]


def _dedup_lower_domains(domains: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for d in domains:
        x = d.strip().lower().lstrip(".")
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
    return tuple(out)


def _split_csv_values(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for x in values:
        if not x:
            continue
        parts = [p.strip() for p in x.split(",")]
        out.extend(p for p in parts if p)
    return out


def _dedup_normalized(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for x in values:
        v = x.strip()
        if not v:
            continue
        k = v.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(v)
    return tuple(out)

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


def _compact_block_hits(hits: list[str], *, limit: int = 10) -> list[str]:
    """
    Compact blocked pattern hits for reporting.

    Input elements can be either "PHRASE" or "PHRASE@enc". We aggregate by PHRASE
    and merge encodings (dedup + preserve order), and cap output by phrase count.
    """
    if not hits:
        return []
    try:
        limit_i = int(limit)
    except Exception:
        limit_i = 10
    if limit_i <= 0:
        return []

    phrase_order: list[str] = []
    encs_by_phrase: dict[str, list[str]] = {}
    enc_seen_by_phrase: dict[str, set[str]] = {}

    for raw in hits:
        if not raw:
            continue
        s = str(raw).strip()
        if not s:
            continue

        phrase, sep, tail = s.rpartition("@")
        if sep and phrase.strip() and tail.strip():
            p = phrase.strip()
            enc_part = tail.strip()
        else:
            p = s
            enc_part = ""

        if p not in encs_by_phrase:
            phrase_order.append(p)
            encs_by_phrase[p] = []
            enc_seen_by_phrase[p] = set()

        if enc_part:
            for enc in enc_part.split(","):
                e = enc.strip()
                if not e:
                    continue
                k = e.lower()
                if k in enc_seen_by_phrase[p]:
                    continue
                enc_seen_by_phrase[p].add(k)
                encs_by_phrase[p].append(e)

    out: list[str] = []
    for p in phrase_order:
        if len(out) >= limit_i:
            break
        encs = encs_by_phrase.get(p) or []
        if encs:
            out.append(f"{p}@{','.join(encs)}")
        else:
            out.append(p)
    return out


def _extract_t5neg_tokens(s: str) -> list[str]:
    """抓出 sanity v2 注入 token（例如 T5NEG_XXXX），僅在出現時啟用 must-match 規則。"""
    if not s:
        return []
    return _dedup_preserve(t.upper() for t in _T5NEG_TOKEN_RE.findall(s))


def _profile_for_category(category: str) -> RuleProfile:
    key = (category or "").strip().upper()
    return RULES_BY_CATEGORY.get(key, DEFAULT_PROFILE)


def _is_weak_evidence_token(token: str, profile: RuleProfile) -> bool:
    """容量/規格數字 token（2TB/650W/2280/CL40 等）屬於弱證據，不能單獨判 match。"""
    return bool(profile.weak_evidence_re.fullmatch(token))


def _is_high_signal_token(token: str, profile: RuleProfile) -> bool:
    """
    高信號 token：長度 >= 4、含數字且含字母，並排除 stoplist/弱證據。
    通常對應型號/料號（如 W680M-ACE、A650GLS）。
    """
    if len(token) < profile.min_high_signal_len:
        return False
    if token in profile.stoplist:
        return False
    if _is_weak_evidence_token(token, profile):
        return False
    has_digit = any(ch.isdigit() for ch in token)
    has_alpha = any("A" <= ch <= "Z" for ch in token)
    return has_digit and has_alpha


def _is_alpha_only_model_token(token: str, profile: RuleProfile) -> bool:
    """Category-configurable: allow a single alpha-only token to count as match evidence (conservative)."""
    if not token or not token.isalpha():
        return False
    if len(token) < profile.alpha_only_model_min_len:
        return False
    if token in profile.stoplist:
        return False
    if token in profile.alpha_only_model_denylist:
        return False
    if _is_weak_evidence_token(token, profile):
        return False
    return True


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


def _policy_match_reason(
    profile: RuleProfile,
    filtered_tokens: list[str],
    weak_support_hits: list[str],
    high_signal_hits: list[str],
) -> str | None:
    if high_signal_hits:
        return "high_signal_token_hit>=1"
    if len(filtered_tokens) >= 2:
        return "filtered_token_hit>=2"
    if profile.match_policy == "default" and len(filtered_tokens) >= 1 and len(weak_support_hits) >= 1:
        return "filtered_token_hit>=1_and_weak_support>=1"
    if (
        profile.allow_alpha_only_model_match
        and len(filtered_tokens) == 1
        and _is_alpha_only_model_token(filtered_tokens[0], profile)
    ):
        return "alpha_only_model_token_hit>=1"
    if profile.allow_alpha_only_brand_match and any(t.isalpha() for t in filtered_tokens):
        return "alpha_only_brand_match"
    return None


def _domain_matches(host: str, domain_suffixes: tuple[str, ...]) -> bool:
    if not domain_suffixes:
        return True
    h = (host or "").lower()
    return any(h == d or h.endswith("." + d) for d in domain_suffixes)


def _is_block_page(
    html: str,
    page_title: str,
    h1: str,
    policy: CrawlPolicy,
) -> tuple[bool, list[str]]:
    text_upper = f"{page_title}\n{h1}\n{html}".upper()
    hits: list[str] = []
    for p in policy.block_patterns:
        if p and p.upper() in text_upper:
            hits.append(p)
    return bool(hits), hits


def _iter_block_pattern_bytes(
    patterns: Iterable[str],
    encodings: Iterable[str],
) -> Iterable[tuple[str, str, bytes]]:
    for pattern in patterns:
        p = (pattern or "").strip()
        if not p:
            continue
        for enc in encodings:
            e = (enc or "").strip()
            if not e:
                continue
            try:
                b = p.encode(e, errors="strict")
            except Exception:
                continue
            if b:
                yield p, e, b


def _is_block_page_bytes(
    raw: bytes,
    patterns: Iterable[str],
    encodings: Iterable[str],
) -> tuple[bool, list[dict[str, str]]]:
    if not raw:
        return False, []
    hits: list[dict[str, str]] = []
    for p, enc, pb in _iter_block_pattern_bytes(patterns, encodings):
        if pb in raw:
            hits.append({"pattern": p, "encoding": enc})
    return bool(hits), hits


def _parse_retry_after_seconds(headers: httpx.Headers) -> float | None:
    if httpx is None:
        return None
    raw = headers.get("Retry-After")
    if not raw:
        return None
    raw = raw.strip()
    if not raw:
        return None
    try:
        return max(float(raw), 0.0)
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = (dt - datetime.now(timezone.utc)).total_seconds()
        return max(delta, 0.0)
    except Exception:
        return None


def _sleep_jitter(min_ms: int, max_ms: int) -> float:
    lo = max(min_ms, 0)
    hi = max(max_ms, 0)
    if hi < lo:
        lo, hi = hi, lo
    delay_s = random.uniform(lo / 1000.0, hi / 1000.0)
    if delay_s > 0:
        time.sleep(delay_s)
    return delay_s


def _cooldown_delay_seconds(
    attempt: int,
    policy: CrawlPolicy,
    retry_after_s: float | None,
) -> float:
    if retry_after_s is not None:
        base = max(0.0, min(retry_after_s, policy.cooldown_max_s))
    else:
        base = min(policy.cooldown_base_s * (2 ** attempt), policy.cooldown_max_s)
    jitter_max = min(max(base * 0.15, 1.0), policy.cooldown_max_s)
    return min(base + random.uniform(0.0, jitter_max), policy.cooldown_max_s)


def _build_crawl_policy(args: argparse.Namespace) -> CrawlPolicy:
    cli_patterns = [x.strip() for x in (args.block_pattern or []) if x and x.strip()]
    env_patterns = _env_list("PCBUILD_T5_BLOCK_PATTERNS")
    block_patterns = tuple(cli_patterns or env_patterns or DEFAULT_BLOCK_PATTERNS)

    cli_domains = [x.strip() for x in (args.block_domain or []) if x and x.strip()]
    env_domains = _env_list("PCBUILD_T5_BLOCK_DOMAINS")
    block_domains = _dedup_lower_domains(cli_domains or env_domains)

    cli_block_encs = _split_csv_values(args.block_encoding or [])
    env_block_encs = _env_list("PCBUILD_T5_BLOCK_ENCODINGS")
    block_encodings = _dedup_normalized(cli_block_encs or env_block_encs or list(DEFAULT_BLOCK_ENCODINGS))

    simulate_block_encoding = (args.simulate_block_encoding or os.getenv("PCBUILD_T5_SIMULATE_BLOCK_ENCODING", "utf-8")).strip()
    if not simulate_block_encoding:
        simulate_block_encoding = "utf-8"

    return CrawlPolicy(
        sleep_min_ms=max(args.sleep_min_ms, 0),
        sleep_max_ms=max(args.sleep_max_ms, 0),
        gap_min_ms=max(args.gap_min_ms, 0),
        gap_max_ms=max(args.gap_max_ms, 0),
        cooldown_base_s=max(args.cooldown_base_s, 0.0),
        cooldown_max_s=max(args.cooldown_max_s, 0.0),
        block_max_retries=max(args.block_max_retries, 0),
        max_total_cooldown_s=max(args.max_total_cooldown_s, 0.0),
        block_patterns=block_patterns,
        block_encodings=block_encodings,
        block_domains=block_domains,
        simulate_block_every=max(args.simulate_block_every, 0),
        simulate_block_encoding=simulate_block_encoding,
    )


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
    blocked_detected: bool
    blocked_patterns_hit: list[str]
    blocked_encoding: str
    block_retry_count: int
    cooldown_total_s: float
    snippet_excerpt: str
    profile_id: str
    reason: str


def _fetch_final_and_snippet( # 追到最終 URL、保留 redirect chain、並只抓固定大小的 HTML 片段（避免抓整頁造成資源浪費）。
    client: httpx.Client,
    url: str,
    max_bytes: int,
) -> tuple[int, str, list[str], bytes, float | None]:
    """
    returns: 
    (status_code: 最後一次回應的 HTTP 狀態碼,
      final_url: 跟隨 redirect 後的最終落地 URL, 
      redirect_chain: redirect 過程中的歷史 URL 列表（證據鏈）,
      html_snippet_bytes: 只讀取前 max_bytes 的 HTML bytes（通常足夠抓 <title>/<h1>）
      retry_after_s: Retry-After 秒數（若有）
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
        snippet_bytes = b"".join(chunks)
        chain = [str(x.url) for x in (r.history or [])] # 原始 URL → 中繼跳轉 → 最終落地 URL 的證據鏈
        if chain:
            chain.append(str(r.url))  # include final_url when redirected
        return r.status_code, str(r.url), chain, snippet_bytes, _parse_retry_after_seconds(r.headers)


def _decode_html_snippet(snippet_bytes: bytes) -> str:
    """Decode HTML using a small encoding fallback set to avoid mojibake (e.g. Big5/CP950)."""
    if not snippet_bytes:
        return ""
    for enc in ("utf-8", "cp950", "big5"):
        try:
            return snippet_bytes.decode(enc, errors="strict")
        except Exception:
            continue
    return snippet_bytes.decode("utf-8", errors="ignore")


def _check_one( # 單筆連結檢查：欄位抽取 → 網域/缺值檢查 → 抓頁面訊號 → token 命中判定 → 回傳 match/mismatch/error 結果。
    client: httpx.Client,
    item: dict[str, Any],
    allow_domains: list[str],
    max_bytes: int,
    crawl_policy: CrawlPolicy,
    item_index: int,
) -> LinkCheckResult:
    url = str(item.get("url") or "")
    title = str(item.get("title") or "")
    sku_hint = str(item.get("sku_hint") or "")
    category = str(item.get("category") or "")
    profile = _profile_for_category(category)
    simulate_block = crawl_policy.simulate_block_every > 0 and item_index % crawl_policy.simulate_block_every == 0

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
            blocked_detected=False,
            blocked_patterns_hit=[],
            blocked_encoding="",
            block_retry_count=0,
            cooldown_total_s=0.0,
            snippet_excerpt="",
            profile_id=profile.profile_id,
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
            blocked_detected=False,
            blocked_patterns_hit=[],
            blocked_encoding="",
            block_retry_count=0,
            cooldown_total_s=0.0,
            snippet_excerpt="",
            profile_id=profile.profile_id,
            reason="domain_not_allowed",
        )

    max_attempts = max(crawl_policy.block_max_retries, 0) + 1
    cooldown_total_s = 0.0
    blocked_hits: list[str] = []
    blocked_encoding = ""

    for attempt in range(max_attempts):
        _sleep_jitter(crawl_policy.sleep_min_ms, crawl_policy.sleep_max_ms)
        try:
            # 測試用：可強制把指定比例的請求視為 blocked，驗證 cooldown/retry 行為。
            if simulate_block:
                simulated_text = "辛苦了，喝杯咖啡休息一下 (simulated block)"
                try:
                    simulated_bytes = simulated_text.encode(crawl_policy.simulate_block_encoding, errors="strict")
                except Exception:
                    simulated_bytes = simulated_text.encode("utf-8", errors="strict")
                http_status, final_url, chain, snippet_bytes, retry_after_s = (200, url, [], simulated_bytes, None)
            else:
                http_status, final_url, chain, snippet_bytes, retry_after_s = _fetch_final_and_snippet(
                    client, url, max_bytes=max_bytes
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
                blocked_detected=False,
                blocked_patterns_hit=[],
                blocked_encoding="",
                block_retry_count=attempt,
                cooldown_total_s=round(cooldown_total_s, 3),
                snippet_excerpt="",
                profile_id=profile.profile_id,
                reason=f"fetch_error:{type(e).__name__}",
            )

        # Enforce allowlist after redirects too.
        if allow_domains and final_url and not _domain_allowed(final_url, allow_domains):
            return LinkCheckResult(
                status="error",
                http_status=http_status,
                url=url,
                final_url=final_url,
                redirect_chain=chain,
                page_title="",
                h1="",
                basis="",
                tokens=[],
                matched_tokens=[],
                filtered_tokens=[],
                stopword_hits=[],
                must_match_tokens=[],
                missing_must_match_tokens=[],
                blocked_detected=False,
                blocked_patterns_hit=[],
                blocked_encoding="",
                block_retry_count=attempt,
                cooldown_total_s=round(cooldown_total_s, 3),
                snippet_excerpt="",
                profile_id=profile.profile_id,
                reason="final_domain_not_allowed",
            )

        snippet = _decode_html_snippet(snippet_bytes)
        page_title = _extract_page_title(snippet)
        h1 = _extract_h1(snippet)
        snippet_excerpt = _strip_tags(snippet)[:500]
        host = (urlparse(final_url).hostname or "").lower()
        text_blocked = False
        text_hits: list[str] = []
        bytes_blocked = False
        bytes_hits: list[dict[str, str]] = []
        if _domain_matches(host, crawl_policy.block_domains):
            text_blocked, text_hits = _is_block_page(snippet, page_title, h1, crawl_policy)
            bytes_blocked, bytes_hits = _is_block_page_bytes(
                snippet_bytes, crawl_policy.block_patterns, crawl_policy.block_encodings
            )
        hits: list[str] = _dedup_preserve(text_hits + [f"{h['pattern']}@{h['encoding']}" for h in bytes_hits])
        byte_encodings = _dedup_preserve(h["encoding"] for h in bytes_hits if h.get("encoding"))
        blocked_encoding = ",".join(byte_encodings)
        if http_status == 429:
            hits = _dedup_preserve(hits + ["HTTP_429"])
        hits = _compact_block_hits(hits, limit=10)
        blocked_detected = text_blocked or bytes_blocked or http_status == 429

        if blocked_detected:
            blocked_hits = hits
            no_retry_left = attempt >= (max_attempts - 1)
            cooldown_budget_exhausted = cooldown_total_s >= crawl_policy.max_total_cooldown_s
            if no_retry_left or cooldown_budget_exhausted:
                return LinkCheckResult(
                    status="error",
                    http_status=http_status,
                    url=url,
                    final_url=final_url,
                    redirect_chain=chain,
                    page_title=page_title,
                    h1=h1,
                    basis="",
                    tokens=[],
                    matched_tokens=[],
                    filtered_tokens=[],
                    stopword_hits=[],
                    must_match_tokens=[],
                    missing_must_match_tokens=[],
                    blocked_detected=True,
                    blocked_patterns_hit=blocked_hits,
                    blocked_encoding=blocked_encoding,
                    block_retry_count=attempt,
                    cooldown_total_s=round(cooldown_total_s, 3),
                    snippet_excerpt=snippet_excerpt,
                    profile_id=profile.profile_id,
                    reason="blocked_cooldown_exhausted",
                )
            delay = _cooldown_delay_seconds(attempt, crawl_policy, retry_after_s)
            remaining = max(crawl_policy.max_total_cooldown_s - cooldown_total_s, 0.0)
            if remaining <= 0:
                continue
            delay = min(delay, remaining)
            if delay > 0:
                time.sleep(delay)
                cooldown_total_s += delay
            continue

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
        stopword_hits = [t for t in matched_tokens if t in profile.stoplist]
        filtered_tokens = [
            t for t in matched_tokens if t not in profile.stoplist and not _is_weak_evidence_token(t, profile)
        ]
        weak_support_hits = [
            t for t in matched_tokens if t not in profile.stoplist and _is_weak_evidence_token(t, profile)
        ]
        high_signal_hits = [t for t in filtered_tokens if _is_high_signal_token(t, profile)]
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
                blocked_detected=False,
                blocked_patterns_hit=[],
                blocked_encoding="",
                block_retry_count=attempt,
                cooldown_total_s=round(cooldown_total_s, 3),
                snippet_excerpt=snippet_excerpt,
                profile_id=profile.profile_id,
                reason="missing_must_match_token",
            )

        match_reason = _policy_match_reason(profile, filtered_tokens, weak_support_hits, high_signal_hits)
        if tokens and match_reason:
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
                blocked_detected=False,
                blocked_patterns_hit=[],
                blocked_encoding="",
                block_retry_count=attempt,
                cooldown_total_s=round(cooldown_total_s, 3),
                snippet_excerpt=snippet_excerpt,
                profile_id=profile.profile_id,
                reason=match_reason,
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
            blocked_detected=False,
            blocked_patterns_hit=[],
            blocked_encoding="",
            block_retry_count=attempt,
            cooldown_total_s=round(cooldown_total_s, 3),
            snippet_excerpt=snippet_excerpt,
            profile_id=profile.profile_id,
            reason="insufficient_filtered_token_hit",
        )
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
        blocked_detected=True,
        blocked_patterns_hit=_compact_block_hits(blocked_hits, limit=10),
        blocked_encoding=blocked_encoding,
        block_retry_count=max_attempts - 1,
        cooldown_total_s=round(cooldown_total_s, 3),
        snippet_excerpt="",
        profile_id=profile.profile_id,
        reason="blocked_cooldown_exhausted",
    )


def main(argv: list[str] | None = None) -> int: # 主程式：CLI 參數 → 讀入 items → 建立 HTTP client → 逐筆檢查 → 輸出 report/quarantine/summary
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Path to parsed JSON (array or JSONL)")
    ap.add_argument("--out-dir", required=True, help="Output directory")
    ap.add_argument("--allow-domain", action="append", default=[], help="Allowlist domain suffix, e.g. coolpc.com.tw")
    ap.add_argument("--max-items", type=int, default=0, help="0 means all items")
    ap.add_argument("--sleep-ms", type=int, default=_env_int("PCBUILD_T5_SLEEP_MS", 150), help="Legacy fixed delay between requests (ms)")
    ap.add_argument("--sleep-min-ms", type=int, default=_env_int("PCBUILD_T5_SLEEP_MIN_MS", 800), help="Per-request pre-sleep jitter min (ms)")
    ap.add_argument("--sleep-max-ms", type=int, default=_env_int("PCBUILD_T5_SLEEP_MAX_MS", 1800), help="Per-request pre-sleep jitter max (ms)")
    ap.add_argument("--gap-min-ms", type=int, default=_env_int("PCBUILD_T5_GAP_MIN_MS", 200), help="Inter-item gap jitter min (ms)")
    ap.add_argument("--gap-max-ms", type=int, default=_env_int("PCBUILD_T5_GAP_MAX_MS", 800), help="Inter-item gap jitter max (ms)")
    ap.add_argument("--cooldown-base-s", type=float, default=_env_float("PCBUILD_T5_COOLDOWN_BASE_S", 120.0), help="Blocked cooldown base seconds")
    ap.add_argument("--cooldown-max-s", type=float, default=_env_float("PCBUILD_T5_COOLDOWN_MAX_S", 1800.0), help="Blocked cooldown cap seconds")
    ap.add_argument("--max-total-cooldown-s", type=float, default=_env_float("PCBUILD_T5_MAX_TOTAL_COOLDOWN_S", 3600.0), help="Per-item max total cooldown seconds")
    ap.add_argument("--block-max-retries", type=int, default=_env_int("PCBUILD_T5_BLOCK_MAX_RETRIES", 3), help="Max retries for blocked/cooldown pages")
    ap.add_argument("--block-pattern", action="append", default=None, help="Blocked page pattern (can repeat)")
    ap.add_argument("--block-encoding", "--block-encodings", dest="block_encoding", action="append", default=None, help="Blocked pattern bytes encoding (can repeat, supports comma-separated). Alias: --block-encodings",)
    ap.add_argument("--block-domain", action="append", default=None, help="Only apply block-pattern detection for these domains (suffix match, can repeat)")
    ap.add_argument("--simulate-block-every", type=int, default=_env_int("PCBUILD_T5_SIMULATE_BLOCK_EVERY", 0), help="Testing only: force every Nth item to enter blocked flow")
    ap.add_argument("--simulate-block-encoding", default=os.getenv("PCBUILD_T5_SIMULATE_BLOCK_ENCODING", "utf-8"), help="Testing only: encoding used to generate simulated block bytes")
    ap.add_argument("--timeout-s", type=float, default=_env_float("PCBUILD_T5_TIMEOUT_S", 12.0))
    ap.add_argument("--max-bytes", type=int, default=120_000, help="Max bytes to read from final page")
    args = ap.parse_args(argv)
    crawl_policy = _build_crawl_policy(args)

    in_path = Path(args.input)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    items = _load_items(in_path)
    if args.max_items and args.max_items > 0:
        items = items[: args.max_items]

    report_path = out_dir / "link_check_report.jsonl"
    quarantine_path = out_dir / "link_check_quarantine.jsonl"
    summary_path = out_dir / "link_check_summary.json"

    client = None
    if httpx is None:
        if crawl_policy.simulate_block_every <= 0:
            raise SystemExit("Missing dependency: httpx (required for live fetch).")
    else:
        # 安全/可預期：不吃環境 proxy；TLS verify 保持預設 True
        # httpx 需顯式 follow_redirects=True 才會追到最終 URL。
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
        for idx, it in enumerate(items, start=1):
            res = _check_one(client, it, args.allow_domain, args.max_bytes, crawl_policy, idx)
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
                "blocked_detected": res.blocked_detected,
                "blocked_patterns_hit": _compact_block_hits(res.blocked_patterns_hit, limit=10),
                "blocked_encoding": res.blocked_encoding,
                "block_retry_count": res.block_retry_count,
                "cooldown_total_s": res.cooldown_total_s,
                "snippet_excerpt": res.snippet_excerpt,
                "profile_id": res.profile_id,
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

            _sleep_jitter(crawl_policy.gap_min_ms, crawl_policy.gap_max_ms)
            if args.sleep_ms > 0:
                time.sleep(args.sleep_ms / 1000.0)

    if client is not None:
        client.close()

    summary_path.write_text(json.dumps(counts, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(counts, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
