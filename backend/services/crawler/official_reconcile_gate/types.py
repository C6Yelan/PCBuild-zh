# backend/services/crawler/official_reconcile_gate/types.py
"""Stable type contracts for T6 official reconciliation gate."""

from __future__ import annotations

from typing import Literal, NotRequired, TypedDict


MatchStatus = Literal["matched", "unmatched", "ambiguous"] # 官網比對結果：已匹配 / 無匹配 / 模稜兩可
DiffSeverity = Literal["low", "medium", "high"] # 差異嚴重程度：低（不影響購買決策）、中（可能影響購買決策）、高（嚴重誤導）
DecisionAction = Literal["autofix", "quarantine", "keep_retail", "skip"] # 最終處置：自動修正 / 隔離審核 / 保留零售值 / 跳過不處理


class ListingInput(TypedDict): # T6 的輸入（零售端一筆商品）
    source: str
    category: str
    title: str
    url: str
    sku_hint: str
    extra: dict[str, object]
    brand_hint: NotRequired[str]
    model_hint: NotRequired[str]
    identifiers: NotRequired[dict[str, str]]


class OfficialCandidate(TypedDict): # 從官網候選清單中挑到的某個候選
    official_source: str
    candidate_url: str
    rank: int
    evidence: dict[str, object]


class OfficialSignals(TypedDict): # 真的去抓官網頁面後抽出來的「信號/規格」
    official_url: str
    http_status: int
    canonical_url: str | None
    product_title: str | None
    model: str | None
    identifiers: dict[str, str] | None
    specs: dict[str, object]
    text_hint: str | None


class MatchDecision(TypedDict): # 比對決策（有無 match、信心度、原因）
    status: MatchStatus
    confidence: float
    reason_code: str
    evidence: dict[str, object]


class MatchDecisionWithOfficial(MatchDecision, total=False): # 比對決策（有無 match、信心度、原因）+ 官網資訊（如果有的話）
    official_source: str
    official_url: str


class DiffItem(TypedDict): # 欄位差異（retail vs official）的一個項目
    field: str
    retail: object
    official: object
    normalized_retail: object | None
    normalized_official: object | None
    severity: DiffSeverity
    reason: str


class PatchResult(TypedDict): # 自動修補結果
    patched_fields: list[str]
    before: dict[str, object]
    after: dict[str, object]


class AuditEntry(TypedDict): # 稽核紀錄（可追溯）
    time: str
    source: str
    rule_id: str
    field: str
    before: object
    after: object
    confidence: float
    notes: str


class T6Result(TypedDict): # T6 統一輸出（給後續 staging / 入庫用）
    match: MatchDecisionWithOfficial
    diff_items: list[DiffItem]
    decision_action: DecisionAction
    decision_reason: str
    patch: PatchResult | None
    audit: list[AuditEntry]
    error: dict[str, object] | None
