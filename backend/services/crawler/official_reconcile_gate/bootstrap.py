# backend/services/crawler/official_reconcile_gate/bootstrap.py
"""Bootstrap helpers for registering builtin T6 pilot plugins."""

from __future__ import annotations

from .adapters.manual_url import ManualUrlAdapter
from .matchers.cpu import CpuMatcher
from .matchers.generic import GenericMatcher
from .registry import (
    get_category_matcher,
    get_source_adapter,
    register_category_matcher,
    register_source_adapter,
)


def register_builtin_plugins() -> None:
    if get_source_adapter("manual_url") is None:
        register_source_adapter(ManualUrlAdapter())

    if get_category_matcher("GENERIC") is None:
        register_category_matcher(GenericMatcher())

    if get_category_matcher("CPU") is None:
        register_category_matcher(CpuMatcher())
