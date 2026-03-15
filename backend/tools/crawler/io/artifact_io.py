"""Shared JSON, artifact, and captured-CLI helpers for crawler tools."""

from __future__ import annotations

import contextlib
from collections.abc import Callable
import io
import json
import os
import sys
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping


def read_json_file(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_json_input(path: str | Path) -> Any:
    if str(path) == "-":
        return json.load(sys.stdin)
    return read_json_file(Path(path))


def require_json_list(payload: Any, *, type_error: str) -> list[Any]:
    if not isinstance(payload, list):
        raise SystemExit(type_error.format(type_name=type(payload).__name__))
    return payload


def require_json_object_list(
    payload: Any,
    *,
    type_error: str,
    item_error: str,
) -> list[dict[str, Any]]:
    rows = require_json_list(payload, type_error=type_error)
    objects: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise SystemExit(item_error.format(index=index, type_name=type(row).__name__))
        objects.append(row)
    return objects


def write_json_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def emit_json_stdout(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False))


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


def write_jsonl_objects(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(dict(row), ensure_ascii=False) + "\n")


def build_artifact_metadata(path: Path, *, base_dir: Path) -> dict[str, Any]:
    data = path.read_bytes()
    stat = path.stat()
    return {
        "relpath": str(path.relative_to(base_dir)),
        "sha256": sha256(data).hexdigest(),
        "bytes": int(stat.st_size),
        "mtime": int(stat.st_mtime),
    }


def extract_last_json_object(text: str) -> dict[str, Any] | None:
    for line in reversed(text.splitlines()):
        stripped = line.strip()
        if not stripped.startswith("{") or not stripped.endswith("}"):
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def run_cli_main(
    main_fn: Callable[[], int],
    argv: list[str],
    *,
    program_name: str | None = None,
) -> tuple[int, str, str]:
    old_argv = sys.argv[:]
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    try:
        sys.argv = [program_name or getattr(main_fn, "__name__", "cli")] + argv
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            try:
                ret = main_fn()
                rc = int(ret) if ret is not None else 0
            except SystemExit as exc:
                rc = int(exc.code) if isinstance(exc.code, int) else 1
        return rc, out_buf.getvalue(), err_buf.getvalue()
    finally:
        sys.argv = old_argv
