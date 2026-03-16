from __future__ import annotations

import os
from pathlib import Path
from uuid import UUID

os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/pcbuild_stage_runtime_test.db")

from backend.tools.db.stage_from_snapshot_runtime import (
    StageFromSnapshotCapture,
    StageFromSnapshotContext,
    emit_stage_from_snapshot_no_items,
    run_stage_from_snapshot_capture,
    stage_snapshot_capture,
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


def test_run_stage_from_snapshot_capture_builds_bundle(monkeypatch) -> None:
    args = type(
        "Args",
        (),
        {
            "source": "coolpc",
            "snapshot_dir": "/tmp/snapshot",
            "note": None,
            "run_id": None,
            "artifact_dir": None,
            "enable_t5": True,
            "t5_limit": 7,
            "t5_min_interval_ms": 1600,
            "t5_timeout_s": 11.0,
            "t5_max_redirects": 6,
            "t5_max_bytes": 1234,
            "t5_block_pattern": ["foo"],
        },
    )()
    context = StageFromSnapshotContext(
        args=args,
        run_id=UUID("00000000-0000-0000-0000-000000000000"),
        source="coolpc",
        app_git_sha="deadbeef",
    )
    artifact_paths = StagingArtifactPaths(
        base_outdir=Path("/tmp/t7/run"),
        dq_outdir=Path("/tmp/t7/run/dq"),
        t5_outdir=Path("/tmp/t7/run/t5"),
    )
    gate_artifacts = StagingGateArtifacts(
        dq_report={"errors": 0},
        dq_meta={"relpath": "dq/dq_report.json"},
        t5_summary={"non_match": 0},
        t5_meta={"relpath": "t5/t5.summary.json"},
    )
    crawl_capture = CrawlParseCapture(
        rc=0,
        stdout_txt='[{"title":"x"}]',
        stderr_txt="",
        items=[{"title": "x"}],
    )
    calls: dict[str, object] = {}

    def fake_resolve_artifact_paths(**kwargs):
        calls["resolve"] = kwargs
        return artifact_paths

    def fake_build_crawl_parse_argv(**kwargs):
        calls["argv"] = kwargs
        return ["--source", "coolpc"]

    def fake_run_crawl_parse_capture(argv):
        calls["capture_argv"] = argv
        return crawl_capture

    def fake_load_gate_artifacts(paths):
        calls["load_gate"] = paths
        return gate_artifacts

    monkeypatch.setattr(
        "backend.tools.db.stage_from_snapshot_runtime.resolve_artifact_paths",
        fake_resolve_artifact_paths,
    )
    monkeypatch.setattr(
        "backend.tools.db.stage_from_snapshot_runtime.build_crawl_parse_argv",
        fake_build_crawl_parse_argv,
    )
    monkeypatch.setattr(
        "backend.tools.db.stage_from_snapshot_runtime.run_crawl_parse_capture",
        fake_run_crawl_parse_capture,
    )
    monkeypatch.setattr(
        "backend.tools.db.stage_from_snapshot_runtime.load_gate_artifacts",
        fake_load_gate_artifacts,
    )

    bundle = run_stage_from_snapshot_capture(context)

    assert bundle.artifact_paths == artifact_paths
    assert bundle.gate_artifacts == gate_artifacts
    assert bundle.crawl_capture == crawl_capture
    assert calls["resolve"] == {
        "artifact_dir": None,
        "run_id": UUID("00000000-0000-0000-0000-000000000000"),
        "enable_t5": True,
    }
    assert calls["argv"] == {
        "source": "coolpc",
        "snapshot_dir": "/tmp/snapshot",
        "run_id": UUID("00000000-0000-0000-0000-000000000000"),
        "dq_outdir": Path("/tmp/t7/run/dq"),
        "t5_outdir": Path("/tmp/t7/run/t5"),
        "t5_limit": 7,
        "t5_min_interval_ms": 1600,
        "t5_timeout_s": 11.0,
        "t5_max_redirects": 6,
        "t5_max_bytes": 1234,
        "t5_block_pattern": ["foo"],
    }
    assert calls["capture_argv"] == ["--source", "coolpc"]
    assert calls["load_gate"] == artifact_paths


def test_stage_snapshot_capture_uses_staging_runtime(monkeypatch) -> None:
    args = type(
        "Args",
        (),
        {
            "source": "coolpc",
            "snapshot_dir": "/tmp/snapshot",
            "note": "demo",
            "run_id": None,
            "artifact_dir": None,
            "enable_t5": True,
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
            t5_outdir=Path("/tmp/t7/run/t5"),
        ),
        gate_artifacts=StagingGateArtifacts(
            dq_report={"errors": 0},
            dq_meta={"relpath": "dq/dq_report.json"},
            t5_summary={"non_match": 0},
            t5_meta={"relpath": "t5/t5.summary.json"},
        ),
        crawl_capture=CrawlParseCapture(
            rc=0,
            stdout_txt="[]",
            stderr_txt="",
            items=[{"title": "x"}],
        ),
    )

    class FakeSession:
        def __enter__(self):
            return "db-session"

        def __exit__(self, exc_type, exc, tb):
            return False

    calls: dict[str, object] = {}

    monkeypatch.setattr(
        "backend.tools.db.stage_from_snapshot_runtime.SessionLocal",
        lambda: FakeSession(),
    )
    monkeypatch.setattr(
        "backend.tools.db.stage_from_snapshot_runtime.stage_snapshot_items",
        lambda db, **kwargs: calls.setdefault("call", {"db": db, **kwargs}) or "unexpected",
    )

    result = stage_snapshot_capture(context, capture)

    assert result["db"] == "db-session"
    assert result["source"] == "coolpc"
    assert result["note"] == "demo"
    assert result["run_id"] == UUID("00000000-0000-0000-0000-000000000000")
    assert result["snapshot_dir"] == "/tmp/snapshot"
    assert result["artifact_dir"] == Path("/tmp/t7/run")
    assert result["items"] == [{"title": "x"}]
    assert result["crawl_rc"] == 0
    assert result["enable_t5"] is True
    assert result["dq_report"] == {"errors": 0}
    assert result["dq_meta"] == {"relpath": "dq/dq_report.json"}
    assert result["t5_summary"] == {"non_match": 0}
    assert result["t5_meta"] == {"relpath": "t5/t5.summary.json"}
