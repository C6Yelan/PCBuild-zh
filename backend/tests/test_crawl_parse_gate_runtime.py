from __future__ import annotations

import logging

from backend.tools.crawler.parse.artifacts import resolve_t5_artifact_paths
from backend.tools.crawler.parse.gate_execution import T5GateConfig, run_t5_gate


def test_run_t5_gate_splits_match_and_non_match_items(monkeypatch, tmp_path) -> None:
    reports = [
        {"status": "match", "reason_code": "MODEL_TOKEN_MATCH"},
        {"status": "mismatch", "reason_code": "MODEL_TOKEN_MISSING"},
    ]
    events: list[dict[str, object]] = []

    monkeypatch.setattr(
        "backend.tools.crawler.parse.t5_gate_runtime.run_link_consistency_check_json",
        lambda argv: 0,
    )
    monkeypatch.setattr(
        "backend.tools.crawler.parse.t5_gate_runtime.read_jsonl_objects",
        lambda path: reports,
    )
    monkeypatch.setattr(
        "backend.tools.crawler.parse.t5_gate_runtime.log_loki_event",
        lambda logger, level=None, **fields: events.append({"level": level, **fields}),
    )

    paths = resolve_t5_artifact_paths(str(tmp_path / "t5"))
    items = [{"title": "A", "url": "https://example.invalid/a"}, {"title": "B", "url": "https://example.invalid/b"}]
    outcome = run_t5_gate(
        config=T5GateConfig(
            source="coolpc",
            run_id="r1",
            app_git_sha="deadbeef",
            snapshot_dir=tmp_path / "snapshot",
            artifacts=paths,
            limit=0,
            min_interval_ms=1500,
            timeout_s=10.0,
            max_redirects=5,
            max_bytes=4194304,
            block_patterns=[],
        ),
        dq_passed_items=items,
        logger=logging.getLogger("test"),
    )

    assert outcome.rc == 2
    assert outcome.passed_items == [items[0]]
    assert outcome.quarantined_items == [items[1]]
    assert outcome.summary == {
        "total": 2,
        "non_match": 1,
        "status_counts": {"match": 1, "mismatch": 1},
        "reason_counts": {"MODEL_TOKEN_MATCH": 1, "MODEL_TOKEN_MISSING": 1},
    }
    assert paths.input_path.exists()
    assert [event["event"] for event in events] == ["t5_link_started", "t5_link_finished"]


def test_run_t5_gate_returns_length_mismatch_error(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "backend.tools.crawler.parse.t5_gate_runtime.run_link_consistency_check_json",
        lambda argv: 0,
    )
    monkeypatch.setattr(
        "backend.tools.crawler.parse.t5_gate_runtime.read_jsonl_objects",
        lambda path: [{"status": "match", "reason_code": "MODEL_TOKEN_MATCH"}],
    )
    monkeypatch.setattr(
        "backend.tools.crawler.parse.t5_gate_runtime.log_loki_event",
        lambda *args, **kwargs: None,
    )

    paths = resolve_t5_artifact_paths(str(tmp_path / "t5"))
    outcome = run_t5_gate(
        config=T5GateConfig(
            source="coolpc",
            run_id="r1",
            app_git_sha="deadbeef",
            snapshot_dir=tmp_path / "snapshot",
            artifacts=paths,
            limit=0,
            min_interval_ms=1500,
            timeout_s=10.0,
            max_redirects=5,
            max_bytes=4194304,
            block_patterns=[],
        ),
        dq_passed_items=[
            {"title": "A", "url": "https://example.invalid/a"},
            {"title": "B", "url": "https://example.invalid/b"},
        ],
        logger=logging.getLogger("test"),
    )

    assert outcome.rc == 2
    assert outcome.summary is None
    assert outcome.error_message == "T5 output error: report/input length mismatch report=1 input=2"
