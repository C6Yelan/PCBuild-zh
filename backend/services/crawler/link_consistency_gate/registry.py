# backend/services/crawler/link_consistency_gate/registry.py
# Link Consistency Gate 策略路由表
from __future__ import annotations

from backend.services.crawler.registry_primitives import lookup_registry_entry, register_aliases
from .strategies.base import NotImplementedStrategy, Strategy
from .strategies.case import CaseStrategy
from .strategies.case_fan import CaseFanStrategy
from .strategies.cooler import CoolerStrategy
from .strategies.cpu import CpuStrategy
from .strategies.expansion_card import ExpansionCardStrategy
from .strategies.gpu import GpuStrategy
from .strategies.hdd import HddStrategy
from .strategies.liquid_cooling import LiquidCoolingStrategy
from .strategies.mb import MbStrategy
from .strategies.psu import PsuStrategy
from .strategies.ram import RamStrategy
from .strategies.ssd import SsdStrategy


REGISTRY: dict[str, Strategy] = { # NotImplementedStrategy 作為預設回應
    "CPU": CpuStrategy(),
    "HDD": HddStrategy(),
    "MB": MbStrategy(),
    "RAM": RamStrategy(),
    "SSD": SsdStrategy(),
    "COOLER": CoolerStrategy(),
    "LIQUID_COOLING": LiquidCoolingStrategy(),
    "GPU": GpuStrategy(),
    "VGA": GpuStrategy(),
    "CASE": CaseStrategy(),
    "CASE_FAN": CaseFanStrategy(),
    "EXPANSION_CARD": ExpansionCardStrategy(),
}
_DEFAULT_STRATEGY: Strategy = NotImplementedStrategy() # 預設策略，當沒有找到對應類別的策略時使用

_psu = PsuStrategy()
register_aliases(REGISTRY, ("POWER", "PSU"), _psu)


def get_strategy(category: str) -> Strategy: # 根據類別名稱從註冊表中獲取對應的策略實例
    # Explicit registry only; no category-specific branching here.
    return lookup_registry_entry(REGISTRY, category, default=_DEFAULT_STRATEGY)
