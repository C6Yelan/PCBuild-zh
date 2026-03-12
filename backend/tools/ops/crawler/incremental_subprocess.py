# backend/tools/ops/incremental_subprocess.py
"""CLI execution and log file helpers for incremental ops runs."""

from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path
from typing import Callable


def run_cli_main(main_fn: Callable[[], int], argv: list[str]) -> tuple[int, str, str]:
    old_argv = sys.argv[:]
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    try:
        sys.argv = [getattr(main_fn, "__name__", "cli")] + argv
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            try:
                ret = main_fn()
                rc = int(ret) if ret is not None else 0
            except SystemExit as exc:
                rc = int(exc.code) if isinstance(exc.code, int) else 1
        return rc, out_buf.getvalue(), err_buf.getvalue()
    finally:
        sys.argv = old_argv


def write_text_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
