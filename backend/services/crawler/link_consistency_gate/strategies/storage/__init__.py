# backend/services/crawler/link_consistency_gate/strategies/storage/__init__.py
from .hdd import HddStrategy
from .ssd import SsdStrategy

__all__ = [
    "HddStrategy",
    "SsdStrategy",
]
