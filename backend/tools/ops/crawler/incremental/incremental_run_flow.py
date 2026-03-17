# backend/tools/ops/crawler/incremental/incremental_run_flow.py
"""Run-flow façade for incremental crawler orchestration helpers."""

from .incremental_phase_runtime import run_incremental_changed_phases, run_incremental_fetch_phase
from .incremental_run_state import (
    IncrementalRunContext,
    apply_incremental_no_change_phase,
    build_incremental_run_context,
    finalize_incremental_run,
    log_incremental_start,
    record_incremental_unhandled_error,
    resolve_incremental_targets,
)


__all__ = [
    "IncrementalRunContext",
    "apply_incremental_no_change_phase",
    "build_incremental_run_context",
    "finalize_incremental_run",
    "log_incremental_start",
    "record_incremental_unhandled_error",
    "resolve_incremental_targets",
    "run_incremental_changed_phases",
    "run_incremental_fetch_phase",
]
