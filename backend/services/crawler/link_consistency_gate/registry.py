# backend/services/crawler/link_consistency_gate/registry.py
# Link Consistency Gate 策略路由表
from __future__ import annotations

from .strategies.base import NotImplementedStrategy, Strategy
from .strategies.case import CaseStrategy
from .strategies.case_fan import CaseFanStrategy
from .strategies.cooler import CoolerStrategy
from .strategies.cpu import CpuStrategy
from .strategies.gpu import GpuStrategy
from .strategies.hdd import HddStrategy
from .strategies.liquid_cooling import LiquidCoolingStrategy
from .strategies.mb import MbStrategy
from .strategies.psu import PsuStrategy
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
REGISTRY["COOLER"] = CoolerStrategy()
REGISTRY["LIQUID_COOLING"] = LiquidCoolingStrategy()
REGISTRY["GPU"] = GpuStrategy()
REGISTRY["VGA"] = GpuStrategy()
REGISTRY["CASE"] = CaseStrategy()
REGISTRY["CASE_FAN"] = CaseFanStrategy()
_psu = PsuStrategy()
REGISTRY["POWER"] = _psu
REGISTRY["PSU"] = _psu


def get_strategy(category: str) -> Strategy: # 根據類別名稱從註冊表中獲取對應的策略實例
    # Explicit registry only; no category-specific branching here.
    return REGISTRY.get(category, _DEFAULT_STRATEGY)
