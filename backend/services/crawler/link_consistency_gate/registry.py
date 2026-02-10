# backend/services/crawler/link_consistency_gate/registry.py
# Link Consistency Gate 策略路由表
from __future__ import annotations

from .strategies.base import NotImplementedStrategy, Strategy


REGISTRY: dict[str, Strategy] = {} # 目前沒有任何實作的策略，僅提供 NotImplementedStrategy 作為預設回應
_DEFAULT_STRATEGY: Strategy = NotImplementedStrategy() # 預設策略，當沒有找到對應類別的策略時使用


def get_strategy(category: str) -> Strategy: # 根據類別名稱從註冊表中獲取對應的策略實例
    # Explicit registry only; no category-specific branching here.
    return REGISTRY.get(category, _DEFAULT_STRATEGY)
