# backend/services/crawler/official_reconcile_gate/policy.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class PatchPolicy:
    """
    Default policy is deny-all.
    Future extension: allow per-category JSON pointer paths.
    """

    allowed_paths_by_category: Mapping[str, frozenset[str]] = field(default_factory=dict)

    def is_allowed(self, *, category: str, path: str) -> bool:
        c = (category or "").upper()
        allowed = self.allowed_paths_by_category.get(c)
        if not allowed:
            return False
        return path in allowed


def default_patch_policy() -> PatchPolicy:
    return PatchPolicy()
