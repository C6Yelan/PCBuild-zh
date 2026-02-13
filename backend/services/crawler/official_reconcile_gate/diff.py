# backend/services/crawler/official_reconcile_gate/diff.py
from __future__ import annotations

from typing import Any

from .types import DiffEntry


_MISSING = object()


def build_diff_entries(retail: Any, official: Any) -> list[DiffEntry]:
    diffs: list[DiffEntry] = []
    _walk(retail, official, path="", out=diffs)
    return diffs


def _walk(retail: Any, official: Any, *, path: str, out: list[DiffEntry]) -> None:
    if type(retail) is dict and type(official) is dict:
        keys = sorted(set(retail.keys()) | set(official.keys()))
        for key in keys:
            key_str = str(key)
            next_path = _join_path(path, key_str)
            _walk(retail.get(key, _MISSING), official.get(key, _MISSING), path=next_path, out=out)
        return

    if type(retail) is list and type(official) is list:
        max_len = max(len(retail), len(official))
        for idx in range(max_len):
            left = retail[idx] if idx < len(retail) else _MISSING
            right = official[idx] if idx < len(official) else _MISSING
            _walk(left, right, path=_join_path(path, str(idx)), out=out)
        return

    if retail is _MISSING and official is _MISSING:
        return
    if retail == official:
        return

    out.append(
        DiffEntry(
            path=path or "/",
            retail_value=None if retail is _MISSING else retail,
            official_value=None if official is _MISSING else official,
            retail_missing=retail is _MISSING,
            official_missing=official is _MISSING,
            severity=_infer_severity(path or "/"),
        )
    )


def _join_path(base: str, token: str) -> str:
    escaped = token.replace("~", "~0").replace("/", "~1")
    if not base:
        return f"/{escaped}"
    return f"{base}/{escaped}"


def _infer_severity(path: str) -> str:
    if path in ("/title", "/official_url"):
        return "warn"
    return "info"
