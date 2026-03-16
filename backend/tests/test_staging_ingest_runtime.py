from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
from uuid import UUID

from backend.services.crawler.staging.conventions import make_item_key
from backend.services.crawler.staging.repo import StagingGateResultWrite
from backend.tools.db.staging_gate_writes import (
    build_json_gate_result_writes,
    build_snapshot_gate_result_writes,
)
from backend.tools.db.staging_write_runtime import stage_items_and_gate_results


def test_build_json_gate_result_writes_resolves_item_key_from_url() -> None:
    items = [
        {
            "title": "CPU item",
            "price": 1000,
            "currency": "TWD",
            "category": "CPU",
            "url": "https://example.invalid/cpu",
            "sku_hint": "CPU-1",
            "extra": {},
        }
    ]

    writes = build_json_gate_result_writes(
        source="coolpc",
        items=items,
        gate_results=[
            {
                "url": "https://example.invalid/cpu",
                "gate_name": "t5_link",
                "status": "pass",
                "detail_json": {"matched": True},
            }
        ],
    )

    assert writes == [
        StagingGateResultWrite(
            item_key=make_item_key("coolpc", items[0]),
            gate_name="t5_link",
            status="pass",
            detail_json={"matched": True},
        )
    ]


def test_build_snapshot_gate_result_writes_marks_t5_fail_on_non_match() -> None:
    item = {
        "title": "GPU item",
        "price": 2000,
        "currency": "TWD",
        "category": "GPU",
        "url": "https://example.invalid/gpu",
        "sku_hint": "GPU-1",
        "extra": {},
    }

    writes = build_snapshot_gate_result_writes(
        source="coolpc",
        snapshot_dir="/tmp/run/snapshot",
        artifact_dir=Path("/tmp/run/artifacts"),
        items=[item],
        crawl_rc=0,
        enable_t5=True,
        dq_report={"errors": 0},
        dq_meta={"relpath": "dq/dq_report.json"},
        t5_summary={"non_match": 1},
        t5_meta={"relpath": "t5/t5.summary.json"},
    )

    assert writes[0].gate_name == "t4_dq"
    assert writes[0].status == "pass"
    assert writes[1].gate_name == "t5_link"
    assert writes[1].status == "fail"
    assert writes[1].detail_json == {
        "artifact_dir": "/tmp/run/artifacts",
        "snapshot_dir": "snapshot",
        "t5_summary": {"relpath": "t5/t5.summary.json"},
        "t5_summary_keys": ["non_match"],
    }


def test_stage_items_and_gate_results_aggregates_repo_counts(monkeypatch) -> None:
    class FakeDB:
        def begin(self):
            return nullcontext()

    monkeypatch.setattr(
        "backend.tools.db.staging_write_runtime.create_ingest_run",
        lambda db, **kwargs: UUID("00000000-0000-0000-0000-000000000001"),
    )
    monkeypatch.setattr(
        "backend.tools.db.staging_write_runtime.upsert_stg_items",
        lambda db, **kwargs: (3, 4),
    )
    monkeypatch.setattr(
        "backend.tools.db.staging_write_runtime.upsert_stg_gate_results",
        lambda db, **kwargs: (5, 6),
    )

    counts = stage_items_and_gate_results(
        FakeDB(),
        source="coolpc",
        note=None,
        run_id=UUID("00000000-0000-0000-0000-000000000000"),
        items=[],
        gate_results=[],
    )

    assert counts.item_inserted == 3
    assert counts.item_updated == 4
    assert counts.gate_inserted == 5
    assert counts.gate_updated == 6
