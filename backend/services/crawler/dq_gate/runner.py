# backend/services/crawler/dq_gate/runner.py
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


DQLevel = Literal["error", "warn", "info"]


@dataclass(frozen=True)
class DQFinding: # 一個資料品質規則的結果
    code: str # 規則代碼
    level: DQLevel # 嚴重度(目前：error/warn/info)
    message: str # 人類可讀的訊息
    metric: float | None = None # 可選的數值指標（如違規筆數、命中幾個url重複等）
    samples: list[str] = field(default_factory=list) #列出少量樣本(避免報表爆炸)


@dataclass(frozen=True)
class DQReport: # 最終報告
    category: str
    total: int
    passed: int
    quarantined: int
    errors: int
    warnings: int
    infos: int
    findings: list[DQFinding]

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "total": self.total,
            "passed": self.passed,
            "quarantined": self.quarantined,
            "errors": self.errors,
            "warnings": self.warnings,
            "infos": self.infos,
            "findings": [asdict(f) for f in self.findings],
        }


@dataclass(frozen=True)
class DQResult: # 最終結果
    passed_items: list[dict[str, Any]] # 通過的項目
    quarantined_items: list[dict[str, Any]] # 隔離的項目
    report: DQReport # 報告

def run_dq_gate(items: list[dict[str, Any]]) -> DQResult:
    """
    最小可跑的 DQ Gate（先做「高訊號、低誤判」規則）：
    - URL 重複：同一批次內 url 應該唯一；重複視為高風險（容易導致錯商品/覆蓋）
    - price==0：多數零售清單 0 元通常是解析失敗或缺值的訊號（先隔離）
    之後再逐步加入：缺值率、範圍、跨欄一致性、分布漂移等（T4 Step 2+）
    """
    if not items: # 空批次直接回報結構一致的結果，避免要特判 None
        report = DQReport(
            category="-",
            total=0,
            passed=0,
            quarantined=0,
            errors=0,
            warnings=0,
            infos=0,
            findings=[DQFinding(code="EMPTY_BATCH", level="warn", message="Empty batch")],
        )
        return DQResult(passed_items=[], quarantined_items=[], report=report)

    # 類別：以第一筆為準，假設同批不會混類别（你的 schema 目前每檔通常同一類別 const）
    category = str(items[0].get("category") or "-")

    # 初始化
    findings: list[DQFinding] = []
    quarantined_idx: set[int] = set() # index 紀錄要隔離的項目

    # 1) url uniqueness (URL 唯一性)
    url_to_first_idx: dict[str, int] = {} # 紀錄 url -> 首次出現的 index，用來判斷是否已經出現過
    dup_urls: dict[str, list[int]] = {} # 紀錄重複 url -> 所有出現的 index 列表，用來產生報表samples
    for i, it in enumerate(items): # enumerate: 取得 index 和 item，e.g., (0, item0), (1, item1), ...
        url = str(it.get("url") or "")
        if not url:
            # T3 理論上已擋掉URL缺失；這裡保險起見記錄
            quarantined_idx.add(i)
            findings.append(
                DQFinding(
                    code="URL_MISSING",
                    level="error",
                    message="url missing (should have been blocked by schema gate)",
                    samples=[f"idx={i}"], # 樣本：缺少 url 的項目索引
                )
            )
            continue
        if url in url_to_first_idx:
            dup_urls.setdefault(url, [url_to_first_idx[url]]).append(i) # 紀錄所有重複 url 的 index，用來產生報表samples
            quarantined_idx.add(i)  # 保留第一筆，其餘隔離
        else:
            url_to_first_idx[url] = i

    if dup_urls:
        sample = []
        # 只取前幾個避免報表爆炸
        for u, idxs in list(dup_urls.items())[:5]:
            sample.append(f"url={u} idxs={idxs}")
        findings.append(
            DQFinding(
                code="DUPLICATE_URL",
                level="error",
                message="duplicate url(s) found in batch; keep first occurrence, quarantine the rest",
                metric=float(len(dup_urls)), # 有幾個不同的重複 url
                samples=sample,
            )
        )

    # 2) price == 0
    zero_price = []
    for i, it in enumerate(items):
        price = it.get("price")
        if isinstance(price, int) and price == 0:
            zero_price.append(i)
            quarantined_idx.add(i)

    if zero_price:
        findings.append(
            DQFinding(
                code="PRICE_ZERO",
                level="warn",
                message="price==0 detected; likely missing/parse issue; quarantined for safety",
                metric=float(len(zero_price)),
                samples=[f"idx={i} url={items[i].get('url','-')}" for i in zero_price[:10]],
            )
        )

    passed_items: list[dict[str, Any]] = []
    quarantined_items: list[dict[str, Any]] = []

    for i, it in enumerate(items):
        if i in quarantined_idx:
            quarantined_items.append(it)
        else:
            passed_items.append(it)

    err_cnt = sum(1 for f in findings if f.level == "error")
    warn_cnt = sum(1 for f in findings if f.level == "warn")
    info_cnt = sum(1 for f in findings if f.level == "info")

    report = DQReport(
        category=category,
        total=len(items),
        passed=len(passed_items),
        quarantined=len(quarantined_items),
        errors=err_cnt,
        warnings=warn_cnt,
        infos=info_cnt,
        findings=findings,
    )
    return DQResult(passed_items=passed_items, quarantined_items=quarantined_items, report=report)
