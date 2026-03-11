from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import backend.tools.ops.chat_staging_inspect as chat_staging_inspect


def test_chat_staging_inspect_cli_supports_request_and_quarantine_listing(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    monkeypatch.setattr(
        chat_staging_inspect,
        "get_ai_settings",
        lambda: SimpleNamespace(ai_raw_snapshot_dir=str(tmp_path)),
    )

    staged_dir = tmp_path / "req-staged"
    staged_dir.mkdir()
    (staged_dir / "meta.json").write_text('{"request_id":"req-staged"}', encoding="utf-8")
    (staged_dir / "staging_record.json").write_text(
        json.dumps({"request_id": "req-staged"}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    quarantined_dir = tmp_path / "req-quarantine"
    quarantined_dir.mkdir()
    (quarantined_dir / "meta.json").write_text('{"request_id":"req-quarantine"}', encoding="utf-8")
    (quarantined_dir / "quarantine_entry.json").write_text(
        json.dumps({"request_id": "req-quarantine"}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    quarantine_index = tmp_path / "_quarantine" / "quarantine_index.jsonl"
    quarantine_index.parent.mkdir(parents=True, exist_ok=True)
    quarantine_index.write_text(
        json.dumps({"request_id": "req-quarantine"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    assert chat_staging_inspect.main(["--request-id", "req-staged"]) == 0
    staged_payload = json.loads(capsys.readouterr().out)
    assert staged_payload["staging_record"] == {"request_id": "req-staged"}

    assert chat_staging_inspect.main(["--request-id", "req-quarantine"]) == 0
    quarantine_payload = json.loads(capsys.readouterr().out)
    assert quarantine_payload["quarantine_entry"] == {"request_id": "req-quarantine"}

    assert chat_staging_inspect.main(["--request-id", "missing"]) == 2
    capsys.readouterr()

    assert chat_staging_inspect.main(["--list-quarantine", "--limit", "5"]) == 0
    listed_payload = json.loads(capsys.readouterr().out)
    assert listed_payload["entries"] == [{"request_id": "req-quarantine"}]
