from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import backend.tools.ops.chat_snapshot_inspect as chat_snapshot_inspect


def test_chat_snapshot_inspect_cli_exit_codes(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setattr(
        chat_snapshot_inspect,
        "get_ai_settings",
        lambda: SimpleNamespace(ai_raw_snapshot_dir=str(tmp_path)),
    )

    ok_dir = tmp_path / "req-ok"
    ok_dir.mkdir()
    for filename, payload in {
        "raw_request.json": {"ok": True},
        "raw_response.json": {"ok": True},
        "meta.json": {"request_id": "req-ok"},
        "request_context.json": {"request_id": "req-ok"},
        "lineage.json": {"request_id": "req-ok"},
    }.items():
        (ok_dir / filename).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    incomplete_dir = tmp_path / "req-missing"
    incomplete_dir.mkdir()
    for filename, payload in {
        "raw_request.json": {"ok": True},
        "raw_response.json": {"ok": True},
        "meta.json": {"request_id": "req-missing"},
    }.items():
        (incomplete_dir / filename).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    assert chat_snapshot_inspect.main(["--request-id", "req-ok"]) == 0
    capsys.readouterr()
    assert chat_snapshot_inspect.main(["--request-id", "req-missing"]) == 1
    capsys.readouterr()
    assert chat_snapshot_inspect.main(["--request-id", "req-404"]) == 2


def test_snapshot_inspect_includes_validation_report(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    monkeypatch.setattr(
        chat_snapshot_inspect,
        "get_ai_settings",
        lambda: SimpleNamespace(ai_raw_snapshot_dir=str(tmp_path)),
    )

    snapshot_dir = tmp_path / "req-ok"
    snapshot_dir.mkdir()
    for filename, payload in {
        "raw_request.json": {"ok": True},
        "raw_response.json": {"ok": True},
        "meta.json": {"request_id": "req-ok"},
        "request_context.json": {"request_id": "req-ok"},
        "validation_report.json": {"passed": True, "reasons": []},
    }.items():
        (snapshot_dir / filename).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    assert chat_snapshot_inspect.main(["--request-id", "req-ok"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["validation_report"] == {"passed": True, "reasons": []}


def test_snapshot_inspect_includes_dq_report(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    monkeypatch.setattr(
        chat_snapshot_inspect,
        "get_ai_settings",
        lambda: SimpleNamespace(ai_raw_snapshot_dir=str(tmp_path)),
    )

    snapshot_dir = tmp_path / "req-ok"
    snapshot_dir.mkdir()
    for filename, payload in {
        "raw_request.json": {"ok": True},
        "raw_response.json": {"ok": True},
        "meta.json": {"request_id": "req-ok"},
        "request_context.json": {"request_id": "req-ok"},
        "dq_report.json": {"passed": True, "reasons": []},
    }.items():
        (snapshot_dir / filename).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    assert chat_snapshot_inspect.main(["--request-id", "req-ok"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["dq_report"] == {"passed": True, "reasons": []}
