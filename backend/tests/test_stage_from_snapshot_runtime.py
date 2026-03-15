from __future__ import annotations

import os
from pathlib import Path
from uuid import UUID

os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/pcbuild_stage_runtime_test.db")

from backend.tools.db.stage_from_snapshot_runtime import (
    StageFromSnapshotCapture,
    StageFromSnapshotContext,
    emit_stage_from_snapshot_no_items,
)
from backend.tools.db.staging_artifacts import StagingArtifactPaths, StagingGateArtifacts
from backend.tools.db.staging_capture import CrawlParseCapture, run_crawl_parse_capture


def test_run_crawl_parse_capture_wraps_stdout_items(monkeypatch) -> None:
    monkeypatch.setattr(
        "backend.tools.db.staging_capture.run_crawl_parse",
        lambda argv: (1, '[{"title":"x","url":"https://example.invalid"}]', "warn"),
    )

    capture = run_crawl_parse_capture(["--source", "coolpc"])

    assert capture.rc == 1
    assert capture.stderr_txt == "warn"
    assert capture.items == [{"title": "x", "url": "https://example.invalid"}]


def test_emit_stage_from_snapshot_no_items_returns_2_when_crawl_rc_zero(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "backend.tools.db.stage_from_snapshot_runtime.log_loki_event",
        lambda *args, **kwargs: None,
    )

    args = type(
        "Args",
        (),
        {
            "source": "coolpc",
            "snapshot_dir": "/tmp/snapshot",
            "note": None,
            "run_id": None,
            "artifact_dir": None,
            "enable_t5": False,
            "t5_limit": 0,
            "t5_min_interval_ms": 1500,
            "t5_timeout_s": 10.0,
            "t5_max_redirects": 5,
            "t5_max_bytes": 4194304,
            "t5_block_pattern": [],
        },
    )()
    context = StageFromSnapshotContext(
        args=args,
        run_id=UUID("00000000-0000-0000-0000-000000000000"),
        source="coolpc",
        app_git_sha="deadbeef",
    )
    capture = StageFromSnapshotCapture(
        artifact_paths=StagingArtifactPaths(
            base_outdir=Path("/tmp/t7/run"),
            dq_outdir=Path("/tmp/t7/run/dq"),
            t5_outdir=None,
        ),
        gate_artifacts=StagingGateArtifacts(
            dq_report=None,
            dq_meta=None,
            t5_summary=None,
            t5_meta=None,
        ),
        crawl_capture=CrawlParseCapture(
            rc=0,
            stdout_txt="[]",
            stderr_txt="parse warning\n",
            items=[],
        ),
    )

    rc = emit_stage_from_snapshot_no_items(
        context,
        capture,
        logger=type("Logger", (), {})(),
        started_monotonic=0.0,
    )

    assert rc == 2
    assert capsys.readouterr().err == "parse warning\n"
