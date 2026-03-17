# backend/services/crawler/link_consistency_gate/strategies/compute/__init__.py
from .cpu import CpuStrategy
from .gpu import GpuStrategy
from .mb import MbStrategy
from .ram import RamStrategy

__all__ = [
    "CpuStrategy",
    "GpuStrategy",
    "MbStrategy",
    "RamStrategy",
]
