# backend/tools/ops/crawler/incremental/incremental_stage_execution.py
"""Parse/stage execution façade for incremental crawler runs."""

from .incremental_parse_execution import run_dry_parse_steps
from .incremental_stage_runtime import run_stage_steps


__all__ = [
    "run_dry_parse_steps",
    "run_stage_steps",
]
