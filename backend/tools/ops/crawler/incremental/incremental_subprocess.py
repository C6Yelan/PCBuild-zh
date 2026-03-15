# backend/tools/ops/incremental_subprocess.py
"""CLI execution and log file helpers for incremental ops runs."""

from __future__ import annotations

from pathlib import Path

from backend.tools.crawler.io.artifact_io import run_cli_main

def write_text_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
