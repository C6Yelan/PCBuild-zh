"""Shared JSON and artifact helpers for crawler CLI tools."""
# backend/tools/crawler/artifact_io.py

from __future__ import annotations

import json
import os
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any


def read_json_file(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def read_jsonl_objects(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {lineno}: {exc.msg}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"expected object at line {lineno}, got {type(row).__name__}")
            rows.append(row)
    return rows


def build_artifact_metadata(path: Path, *, base_dir: Path) -> dict[str, Any]:
    data = path.read_bytes()
    stat = path.stat()
    return {
        "relpath": str(path.relative_to(base_dir)),
        "sha256": sha256(data).hexdigest(),
        "bytes": int(stat.st_size),
        "mtime": int(stat.st_mtime),
    }
