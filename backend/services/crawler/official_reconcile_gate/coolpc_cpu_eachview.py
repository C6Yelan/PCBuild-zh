# backend/services/crawler/official_reconcile_gate/coolpc_cpu_eachview.py
"""Helpers to attach CPU official URLs from CoolPC eachview snapshot."""

from __future__ import annotations

import html as html_lib
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

_RE_BLOCK = re.compile(
    r"<div\s+class\s*=\s*['\"]?w['\"]?\s*>\s*(?P<ibuy>[^<]+?)\s*</div>"
    r"(?P<body>.*?)(?=<div\s+class\s*=\s*['\"]?w['\"]?\s*>|$)",
    flags=re.IGNORECASE | re.DOTALL,
)
_RE_ANCHOR = re.compile(
    r"<a\b[^>]*href\s*=\s*(?P<q>['\"])(?P<href>.*?)(?P=q)[^>]*>(?P<label>.*?)</a>",
    flags=re.IGNORECASE | re.DOTALL,
)
_RE_TAG = re.compile(r"<[^>]+>", flags=re.DOTALL)
_RE_WS = re.compile(r"\s+", flags=re.UNICODE)


def extract_ibuy_to_official_urls(html_text: str) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}

    for block in _RE_BLOCK.finditer(html_text):
        ibuy_token = _clean_text(block.group("ibuy"))
        if not ibuy_token:
            continue

        body = block.group("body")
        for anchor in _RE_ANCHOR.finditer(body):
            label = _clean_text(_RE_TAG.sub(" ", anchor.group("label")))
            if "開箱討論" not in label:
                continue

            href = _clean_text(anchor.group("href"))
            if not href:
                continue

            href = html_lib.unescape(href)
            urls = mapping.setdefault(ibuy_token, [])
            seen_set = seen.setdefault(ibuy_token, set())
            if href not in seen_set:
                urls.append(href)
                seen_set.add(href)

    return mapping


def attach_official_urls_from_eachview(
    items: list[dict],
    *,
    eachview_path: str,
) -> dict[str, int]:
    html_text = _read_eachview_html(eachview_path)
    mapping = extract_ibuy_to_official_urls(html_text)

    counters: dict[str, int] = {
        "total_cpu": 0,
        "attached": 0,
        "already_present": 0,
        "no_ibuy": 0,
        "no_match": 0,
    }

    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("category") != "CPU":
            continue

        counters["total_cpu"] += 1
        extra = item.get("extra")
        if not isinstance(extra, dict):
            extra = {}
            item["extra"] = extra

        if "official_url" in extra or "official_urls" in extra:
            counters["already_present"] += 1
            continue

        ibuy_token = _extract_ibuy(item.get("url"))
        if not ibuy_token:
            counters["no_ibuy"] += 1
            continue

        matched_urls = mapping.get(ibuy_token)
        if not matched_urls:
            counters["no_match"] += 1
            continue

        if len(matched_urls) == 1:
            extra["official_url"] = matched_urls[0]
        else:
            extra["official_urls"] = list(matched_urls)
        counters["attached"] += 1

    return counters


def _read_eachview_html(eachview_path: str) -> str:
    path = Path(eachview_path)
    if path.is_dir():
        body_path = path / "body.txt"
        if not body_path.is_file():
            raise ValueError(f"body.txt not found under directory: {eachview_path}")
        target = body_path
    elif path.is_file():
        target = path
    else:
        raise ValueError(f"eachview path not found: {eachview_path}")

    try:
        return target.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read eachview file: {exc}") from exc


def _extract_ibuy(url_value: object) -> str | None:
    if not isinstance(url_value, str) or not url_value.strip():
        return None
    parsed = urlparse(url_value)
    qs = parse_qs(parsed.query)
    ibuy_val = (qs.get("iBuy") or [None])[0]
    if ibuy_val is None:
        return None
    decoded = unquote(ibuy_val).strip()
    if not decoded:
        return None
    return decoded


def _clean_text(value: str) -> str:
    return _RE_WS.sub(" ", html_lib.unescape(value)).strip()
