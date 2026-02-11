# backend/services/crawler/link_consistency_gate/registry.py
# Link Consistency Gate 策略路由表
from __future__ import annotations

from .strategies.base import NotImplementedStrategy, Strategy
from .strategies.cpu import CpuStrategy
from .strategies.hdd import HddStrategy
from .strategies.mb import MbStrategy
from .strategies.ram import RamStrategy
from .strategies.ssd import SsdStrategy


REGISTRY: dict[str, Strategy] = {} # NotImplementedStrategy 作為預設回應
_DEFAULT_STRATEGY: Strategy = NotImplementedStrategy() # 預設策略，當沒有找到對應類別的策略時使用

# Explicit registry only; no category-specific branching here.
REGISTRY["CPU"] = CpuStrategy()
REGISTRY["HDD"] = HddStrategy()
REGISTRY["MB"] = MbStrategy()
REGISTRY["RAM"] = RamStrategy()
REGISTRY["SSD"] = SsdStrategy()


def get_strategy(category: str) -> Strategy: # 根據類別名稱從註冊表中獲取對應的策略實例
    # Explicit registry only; no category-specific branching here.
    return REGISTRY.get(category, _DEFAULT_STRATEGY)
