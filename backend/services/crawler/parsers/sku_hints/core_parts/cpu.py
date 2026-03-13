# backend/services/crawler/parsers/sku_hints/cpu.py
from __future__ import annotations

import re

from ..common import first_line

_CPU_SKU_RE = re.compile( # 支援 Intel 與 AMD 常見型號格式
    r"(?i)(?<![A-Za-z0-9])("
    r"(?:i[3579]-\d{4,5}[a-z0-9]{0,6})|"
    r"(?:core\s+ultra\s+\d+\s+\d{3}[a-z0-9]{0,6})|"
    r"(?:ryzen\s+[3579]\s+\d{4,5}[a-z0-9]{0,6})|"
    r"(?:amd\s+)?r[3579]\s*\d{4,5}[a-z0-9]{0,6}|"
    r"(?:xeon\s+w\d+-\d{4,5}[a-z0-9]{0,6})|"
    r"(?:ryzen\s+tr\s+(?:pro\s+)?\d{4,5}[a-z0-9]{0,6})|"
    r"(?:threadripper\s+(?:pro\s+)?\d{4,5}[a-z0-9]{0,6})"
    r")(?=[^A-Za-z0-9]|$)"
)

_AMD_HINT_RE = re.compile( # 用來推斷是否為 AMD 品牌的提示字串
    r"(?i)(?<![A-Za-z0-9])("
    r"(?:ryzen|threadripper|epyc|athlon)|"
    r"(?:amd\s+)?r[3579]\s*\d{4,5}[a-z0-9]{0,6}"
    r")(?=[^A-Za-z0-9]|$)"
)
_INTEL_HINT_RE = re.compile( # 用來推斷是否為 Intel 品牌的提示字串
    r"(?i)(?<![A-Za-z0-9])("
    r"(?:core\s+ultra\s+\d+\s+\d{3}[a-z0-9]{0,6})|"
    r"(?:core\s+i\d)|"
    r"(?:i[3579]-\d{4,5}[a-z0-9]{0,6})|"
    r"(?:xeon|pentium|celeron|atom|intel)"
    r")(?=[^A-Za-z0-9]|$)"
)
_ACCESSORY_RE = re.compile(r"(?i)(水冷|散熱器?|冷卻|優惠加購|加購|(?<![含無附])風扇)") # CPU 配件關鍵字

# 強訊號：直接視為 bundle（條件價/活動價）
_BUNDLE_STRONG_RE = re.compile(
    r"(?i)(組裝價|組裝/升級|限組裝|限搭機|任搭主機板|任搭U|搭購|套裝|優惠組合|大全配|專案|X3D專案)"
)

# 弱訊號：僅在「明確邊界」出現的 '任搭' 才算
# - 允許：在【】或[] 內、或前後是空白/標點/字串邊界
# - 避免：像 '65W任搭' 這種黏在英數後面的誤判
_BUNDLE_WEAK_RE = re.compile(
    r"(?i)(?:(?<=【)|(?<=\[)|(?<=\s)|^)任搭(?:(?=】)|(?=\])|(?=\s|$|[，,。．/]))"
)

# CPU 清單中「明顯不是 CPU」的污染訊號（用來把混入的主機板/活動頁項目標成 accessory）
# 注意：只在 sku_hint 抽不到時才會觸發，避免誤傷正常 CPU
_NON_CPU_RE = re.compile(
    r"(?i)(主機板|motherboard|ATX|mATX|ITX|DDR[45]|Wi-?Fi|LAN|PCIe|M\.2|"
    r"\b[XYZBH]\d{3,4}\b|PRIME|EAGLE|AORUS|TUF|STRIX|CSM|"
    r"ASUS|GIGABYTE|MSI|ASROCK|華碩|技嘉|微星|華擎)"
)

def _infer_brand_hint(title: str, sku_hint: str | None) -> str | None: # 根據標題或型號提示推斷品牌（AMD 或 Intel）
    text = (sku_hint or title or "").strip()
    if not text:
        return None
    if _AMD_HINT_RE.search(text):
        return "AMD"
    if _INTEL_HINT_RE.search(text):
        return "Intel"
    return None

def extract_cpu_sku_hint(title: str) -> str | None: # 從標題中抽取 CPU 型號提示
    line = first_line(title)
    m = _CPU_SKU_RE.search(line)
    return m.group(1) if m else None

def extract_cpu_hints(title: str) -> tuple[str | None, dict[str, object]]:
    line = first_line(title)
    sku_hint = extract_cpu_sku_hint(line)

    # 有「限組裝/任搭/專案」等條件字樣，就視為 bundle/條件價
    is_bundle = bool(_BUNDLE_STRONG_RE.search(line)) or bool(_BUNDLE_WEAK_RE.search(line))

    # 1) 明確配件字樣（散熱/水冷/加購等）
    # 2) 若 sku_hint 抽不到，且看起來像主機板/平台活動（ATX/LAN/WIFI/X870…），視為混入的非 CPU 項目
    is_accessory = bool(_ACCESSORY_RE.search(line)) or (sku_hint is None and bool(_NON_CPU_RE.search(line)))

    extra = {
        "brand_hint": _infer_brand_hint(line, sku_hint),
        "model_hint": sku_hint,
        "is_bundle": is_bundle,
        "is_accessory": is_accessory,
    }
    return sku_hint, extra
