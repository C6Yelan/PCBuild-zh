# backend/services/crawler/link_consistency_gate/engine_support.py
from __future__ import annotations

import base64
import re
from urllib.parse import unquote, urlparse

from .types import BlockDetectionConfig

RE_WS = re.compile(r"\s+", flags=re.UNICODE)


def compile_block_patterns(cfg: BlockDetectionConfig) -> list[re.Pattern[str]]:
    if not cfg.enabled:
        return []
    regexes: list[re.Pattern[str]] = []
    for pattern in cfg.patterns:
        try:
            regexes.append(re.compile(pattern, flags=re.IGNORECASE))
        except re.error as exc:
            raise ValueError(f"invalid block pattern regex: {pattern!r}: {exc}") from exc
    return regexes


def one_line(text: str, *, max_len: int) -> str:
    value = RE_WS.sub(" ", text or "").strip()
    if len(value) > max_len:
        value = value[: max_len - 3] + "..."
    return value


def extract_raw_query_param(query: str, key: str) -> str | None:
    if not query or not key:
        return None
    regex = re.compile(rf"(?:^|&){re.escape(key)}=([^&]+)", flags=re.UNICODE)
    match = regex.search(query)
    if not match:
        return None
    value = match.group(1)
    if not value:
        return None
    return value


def coolpc_try_decode_ibuy(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except Exception:
        return None

    host = (parsed.hostname or "").lower()
    if host != "www.coolpc.com.tw":
        return None
    if (parsed.path or "") != "/evaluate.php":
        return None

    raw_ibuy = extract_raw_query_param(parsed.query or "", "iBuy")
    if not raw_ibuy:
        return None

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


__all__ = [
    "compile_block_patterns",
    "coolpc_try_decode_ibuy",
    "extract_raw_query_param",
    "one_line",
]
