# backend/services/crawler/official_reconcile_gate/matchers/cpu.py
"""CPU matcher for T6 pilot flow."""

from __future__ import annotations

from .generic import GenericMatcher


class CpuMatcher(GenericMatcher):
    category = "CPU"
