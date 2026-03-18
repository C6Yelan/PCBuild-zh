"""Compatibility shim for chat demand-resolution helpers."""

from __future__ import annotations

from backend.services.chat.service.demand import (
    DemandResolution,
    log_demand_resolution,
    resolve_demand,
)

__all__ = [
    "DemandResolution",
    "log_demand_resolution",
    "resolve_demand",
]
