# backend/services/crawler/parsers/sku_hints/mb.py
from __future__ import annotations

import re

_SPLIT_RE = re.compile(r"[（(【]")  # 遇到括號/【】就切掉後面的規格
_WS_RE = re.compile(r"\s+")

# 這些多半是規格或外形，不應納入 sku_hint（可依你資料再擴充）
_STOPWORDS = {
    "ATX", "M-ATX", "MATX", "MICRO", "E-ATX", "ITX", "MINI-ITX",
    "DDR4", "DDR5", "WIFI6", "WIFI6E", "WIFI7",
    "LAN", "RGB", "ARGB",
}

# 反向接頭/背插 生態：ASUS BTF、MSI Project Zero(PZ)、GIGABYTE STEALTH
# 官方各自說明其「背面/隱藏接口」概念：:contentReference[oaicite:2]{index=2}
_VARIANT_ALIASES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\bBTF\b"), "BTF"),
    (re.compile(r"(?i)\bPROJECT\s*ZERO\b"), "PZ"),
    (re.compile(r"(?i)\bPZ\b"), "PZ"),
    (re.compile(r"(?i)\bSTEALTH\b"), "STEALTH"),
]

def extract_mb_sku_hint(title: str) -> str | None:
    if not title:
        return None

    # 1) 先切掉規格描述
    head = _SPLIT_RE.split(title, 1)[0]
    head = _WS_RE.sub(" ", head).strip()

    # 2) 取出 variant（背插/隱藏接口）標記：BTF / PZ / STEALTH
    variant: str | None = None
    for pat, norm in _VARIANT_ALIASES:
        if pat.search(head):
            variant = norm
            break

    # 3) token 化，找到第一個含數字的 token 作為型號錨點
    tokens = [t for t in head.split(" ") if t]
    idx = None
    for i, t in enumerate(tokens):
        if any(ch.isdigit() for ch in t):
            idx = i
            break
    if idx is None:
        return variant  # 只剩下變體標記時，至少不回傳 null

    # 4) 從錨點往後收集少量 token（避免把規格詞塞進來）
    picked: list[str] = []
    for t in tokens[idx:]:
        t0 = t.strip().strip(",/")

        # 碰到明顯規格/外形就停止
        if t0.upper() in _STOPWORDS:
            break

        # 只接受較短、偏型號的 token（過長通常是描述）
        if len(t0) > 18:
            break

        picked.append(t0)

        # 防止過度擴張：主機板型號通常 1~4 token 足夠
        if len(picked) >= 4:
            break

    base = " ".join(picked).strip()
    if not base:
        return variant

    # 5) 若 variant 存在但 base 未包含，則附加在後（保留差異性）
    if variant and variant not in base.upper():
        return f"{base} {variant}"
    return base
