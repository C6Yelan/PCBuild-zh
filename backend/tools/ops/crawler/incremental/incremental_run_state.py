"""Run-state façade for incremental crawler runs."""

from .incremental_context_runtime import (
    IncrementalRunContext,
    build_incremental_run_context,
    log_incremental_start,
    resolve_incremental_targets,
)
from .incremental_summary_runtime import (
    apply_incremental_no_change_phase,
    finalize_incremental_run,
    log_incremental_skip_events,
    record_incremental_unhandled_error,
    set_incremental_skip_summary,
)


__all__ = [
    "IncrementalRunContext",
    "apply_incremental_no_change_phase",
    "build_incremental_run_context",
    "finalize_incremental_run",
    "log_incremental_skip_events",
    "log_incremental_start",
    "record_incremental_unhandled_error",
    "resolve_incremental_targets",
    "set_incremental_skip_summary",
]
