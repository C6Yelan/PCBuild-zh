# backend/services/crawler/encoding.py
from __future__ import annotations

import re
from typing import Mapping, Tuple, Dict, Any

# <meta charset="utf-8">
_META_CHARSET_RE = re.compile(
    r'<meta\s+[^>]*charset=["\']?\s*([a-zA-Z0-9._-]+)\s*["\']?',
    flags=re.IGNORECASE,
)

# <meta http-equiv="Content-Type" content="text/html; charset=big5">
_META_HTTP_EQUIV_RE = re.compile(
    r'<meta\s+[^>]*http-equiv=["\']?\s*content-type\s*["\']?[^>]*content=["\'][^"\']*charset\s*=\s*([a-zA-Z0-9._-]+)',
    flags=re.IGNORECASE,
)

def _charset_from_content_type(headers: Mapping[str, str]) -> str | None:
    # Content-Type: text/html; charset=big5
    ct = None
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v
            break
    if not ct:
        return None
    parts = [p.strip() for p in ct.split(";")]
    for p in parts[1:]:
        if p.lower().startswith("charset="):
            return p.split("=", 1)[1].strip().strip('"').strip("'") or None
    return None

def _charset_from_meta(raw: bytes) -> str | None:
    # Only inspect early bytes; HTML spec sniffing uses early bytes.
    head = raw[:4096].decode("ascii", errors="ignore")
    m = _META_CHARSET_RE.search(head)
    if m:
        return m.group(1)
    m = _META_HTTP_EQUIV_RE.search(head)
    if m:
        return m.group(1)
    return None

def _guess_charset_charset_normalizer(raw: bytes) -> str | None:
    try:
        from charset_normalizer import from_bytes  # type: ignore
    except Exception:
        return None
    try:
        best = from_bytes(raw).best()
        return best.encoding if best else None
    except Exception:
        return None

def decode_html(raw: bytes, headers: Mapping[str, str] | None = None) -> Tuple[str, Dict[str, Any]]:
    """
    Decode HTML bytes into text with a traceable decision path.

    Returns:
        (text, info)
        info keys: detected_encoding, decode_source, lossy_decode
    """
    headers = headers or {}
    candidates: list[tuple[str, str]] = []  # (encoding, source)

    # BOM quick checks
    if raw.startswith(b"\xef\xbb\xbf"):
        candidates.append(("utf-8-sig", "bom"))
    elif raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        candidates.append(("utf-16", "bom"))

    enc_h = _charset_from_content_type(headers)
    if enc_h:
        candidates.append((enc_h, "header"))

    enc_m = _charset_from_meta(raw)
    if enc_m:
        candidates.append((enc_m, "meta"))

    enc_g = _guess_charset_charset_normalizer(raw)
    if enc_g:
        candidates.append((enc_g, "guess"))

    # Safe fallbacks for TW sites
    for enc in ("utf-8", "cp950", "big5"):
        candidates.append((enc, "fallback"))

    # Deduplicate preserving order (case-insensitive)
    seen: set[str] = set()
    uniq: list[tuple[str, str]] = []
    for enc, src in candidates:
        key = enc.lower()
        if key not in seen:
            seen.add(key)
            uniq.append((enc, src))

    # Strict decode attempts first (no irreversible U+FFFD)
    for enc, src in uniq:
        try:
            text = raw.decode(enc, errors="strict")
            return text, {
                "detected_encoding": enc,
                "decode_source": src,
                "lossy_decode": False,
            }
        except Exception:
            continue

    # Last resort: lossy decode to ensure we return something; mark it clearly.
    text = raw.decode("utf-8", errors="replace")
    return text, {
        "detected_encoding": "utf-8",
        "decode_source": "replace",
        "lossy_decode": True,
    }
