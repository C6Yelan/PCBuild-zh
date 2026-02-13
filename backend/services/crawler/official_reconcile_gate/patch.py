# backend/services/crawler/official_reconcile_gate/patch.py
from __future__ import annotations

import copy
from typing import Any

from .policy import PatchPolicy
from .types import DiffEntry, PatchOp


def build_patch_plan(diffs: list[DiffEntry], *, category: str, policy: PatchPolicy) -> list[PatchOp]:
    ops: list[PatchOp] = []
    for d in diffs:
        if not policy.is_allowed(category=category, path=d.path):
            continue

        op = _pick_op(d)
        if op == "remove":
            ops.append(PatchOp(op="remove", path=d.path, reason="POLICY_ALLOW"))
            continue
        ops.append(PatchOp(op=op, path=d.path, value=d.official_value, reason="POLICY_ALLOW"))
    return ops


def apply_patch_ops(record: dict[str, Any], ops: list[PatchOp]) -> dict[str, Any]:
    target = copy.deepcopy(record)
    for op in ops:
        _apply_one(target, op)
    return target


def _pick_op(d: DiffEntry) -> str:
    if d.retail_value is None and d.official_value is not None:
        return "add"
    if d.retail_value is not None and d.official_value is None:
        return "remove"
    return "replace"


def _apply_one(target: dict[str, Any], op: PatchOp) -> None:
    tokens = _parse_pointer(op.path)
    if not tokens:
        return

    parent = target
    for token in tokens[:-1]:
        next_obj = parent.get(token)
        if not isinstance(next_obj, dict):
            next_obj = {}
            parent[token] = next_obj
        parent = next_obj

    leaf = tokens[-1]
    if op.op == "remove":
        parent.pop(leaf, None)
        return

    parent[leaf] = op.value


def _parse_pointer(path: str) -> list[str]:
    if path == "":
        return []
    if not path.startswith("/"):
        raise ValueError(f"invalid JSON pointer path: {path!r}")

    out: list[str] = []
    for token in path.split("/")[1:]:
        out.append(token.replace("~1", "/").replace("~0", "~"))
    return out
