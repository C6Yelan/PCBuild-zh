# backend/tests/test_chat_service_p8_dq.py
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import backend.services.chat.service as chat_service
import backend.tools.ops.chat_snapshot_inspect as chat_snapshot_inspect
from backend.services.chat.contracts import ChatRequest
from backend.services.chat.dq import evaluate_text_dq


class _FakeSettings:
    def __init__(self, raw_snapshot_dir: str) -> None:
        self.ai_oai_base_url = "https://example.invalid/v1"
        self.ai_oai_api_key = None
        self.ai_model = "gpt-4o-mini"
        self.ai_timeout_seconds = 10.0
        self.ai_max_output_chars = 200
        self.ai_provider = "openai_compat"
        self.ai_raw_snapshot_dir = raw_snapshot_dir
        self.p2_max_value_len = 120
        self.p2_max_specs_per_part = 12
        self.p2_spec_whitelist_by_category = {}


def _context_candidates() -> dict[str, list[dict[str, object]]]:
    return {
        "CPU": [
            {
                "part_id": "cpu-1",
                "category": "CPU",
                "display_name": "AMD Ryzen 5 5600",
                "key_specs": {"socket_hint": "AM4"},
                "price": 3200,
                "source": "coolpc",
                "source_url": "https://example.invalid/cpu-1",
                "snapshot_id": None,
                "run_id": "run-cpu-1",
            }
        ],
        "MB": [
            {
                "part_id": "mb-1",
                "category": "MB",
                "display_name": "B550M PRO",
                "key_specs": {"socket_hint": "AM4"},
                "price": 2500,
                "source": "coolpc",
                "source_url": "https://example.invalid/mb-1",
                "snapshot_id": None,
                "run_id": "run-mb-1",
            }
        ],
    }


def _provider_result(
    *,
    text: str,
    request_id: str,
) -> chat_service._ProviderCallResult:
    return chat_service._ProviderCallResult(
        text=text,
        endpoint="https://example.invalid/v1/chat/completions",
        status_code=200,
        request_headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Client-Request-Id": request_id,
        },
        request_json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        response_headers={"x-request-id": "up-1"},
        response_json={"choices": [{"message": {"content": text}}]},
        raw_response_text=json.dumps({"choices": [{"message": {"content": text}}]}, ensure_ascii=False),
        upstream_request_id="up-1",
    )


def test_evaluate_text_dq_passes_for_normal_text_with_context_hit() -> None:
    report = evaluate_text_dq(
        text="建議先選 CPU 處理器，再搭配 AM4 主機板，這樣文書機會比較穩定。",
        request_categories=["CPU", "MB"],
        compressed_candidates=_context_candidates(),
        context_pack_text="CTX",
        triggered_retrieval=True,
    )

    assert report.passed is True
    assert report.reasons == []
    assert report.metrics["keyword_hit_count"] >= 1


def test_evaluate_text_dq_rejects_too_short() -> None:
    report = evaluate_text_dq(
        text="短",
        request_categories=[],
        compressed_candidates={},
        context_pack_text=None,
        triggered_retrieval=False,
    )

    assert report.passed is False
    assert "too_short" in report.reasons


def test_evaluate_text_dq_rejects_unsure_without_next_step() -> None:
    report = evaluate_text_dq(
        text="不知道，無法回答。",
        request_categories=[],
        compressed_candidates={},
        context_pack_text=None,
        triggered_retrieval=False,
    )

    assert report.passed is False
    assert "unsure_without_next_step" in report.reasons


def test_evaluate_text_dq_allows_unsure_with_next_step() -> None:
    report = evaluate_text_dq(
        text="目前資料不足，請補充預算與用途。",
        request_categories=[],
        compressed_candidates={},
        context_pack_text=None,
        triggered_retrieval=False,
    )

    assert "unsure_without_next_step" not in report.reasons


def test_evaluate_text_dq_rejects_high_repetition() -> None:
    report = evaluate_text_dq(
        text="同一句話。\n同一句話。\n同一句話。",
        request_categories=[],
        compressed_candidates={},
        context_pack_text=None,
        triggered_retrieval=False,
    )

    assert report.passed is False
    assert "high_repetition" in report.reasons


def test_evaluate_text_dq_rejects_low_context_hit() -> None:
    report = evaluate_text_dq(
        text="今天天氣很好，去散步吧。",
        request_categories=["CPU", "MB"],
        compressed_candidates=_context_candidates(),
        context_pack_text="CTX",
        triggered_retrieval=True,
    )

    assert report.passed is False
    assert "low_context_hit" in report.reasons


def test_evaluate_text_dq_rejects_context_category_empty() -> None:
    report = evaluate_text_dq(
        text="請先比較 CPU 與主機板。",
        request_categories=["CPU", "MB"],
        compressed_candidates={"CPU": _context_candidates()["CPU"], "MB": []},
        context_pack_text="CTX",
        triggered_retrieval=True,
    )

    assert report.passed is False
    assert "context_category_empty" in report.reasons


def test_evaluate_text_dq_rejects_context_missing_required_specs() -> None:
    report = evaluate_text_dq(
        text="這塊主機板可以考慮。",
        request_categories=["MB"],
        compressed_candidates={
            "MB": [
                {
                    "part_id": "mb-1",
                    "category": "MB",
                    "display_name": "B650M",
                    "key_specs": {"chipset_hint": "B650"},
                    "source": "coolpc",
                    "source_url": "https://example.invalid/mb-1",
                    "snapshot_id": None,
                    "run_id": "run-mb-1",
                }
            ]
        },
        context_pack_text="CTX",
        triggered_retrieval=True,
    )

    assert report.passed is False
    assert "context_missing_required_specs" in report.reasons


def test_generate_chat_reply_returns_dq_failed_for_low_quality_text(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_service,
        "_generate_provider_result",
        lambda **kwargs: _provider_result(text="短", request_id=kwargs["request_id"]),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type == "dq_failed"
    assert response.text.startswith("目前資料不足，請補充需求後再試。request_id=")

    snapshot_dir = tmp_path / response.request_id
    dq_report = json.loads((snapshot_dir / "dq_report.json").read_text(encoding="utf-8"))
    assert dq_report["passed"] is False
    assert "too_short" in dq_report["reasons"]

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["dq_status"] == "fail"
    assert "too_short" in meta["dq_reasons"]


def test_generate_chat_reply_keeps_success_when_dq_passes(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_service,
        "_generate_provider_result",
        lambda **kwargs: _provider_result(
            text="這是一段正常的回覆內容，包含足夠資訊。",
            request_id=kwargs["request_id"],
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type is None
    snapshot_dir = tmp_path / response.request_id
    dq_report = json.loads((snapshot_dir / "dq_report.json").read_text(encoding="utf-8"))
    assert dq_report["passed"] is True

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["dq_status"] == "pass"
    assert meta["dq_reasons"] == []


def test_generate_chat_reply_skips_dq_when_gate_fails(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_service,
        "_generate_provider_result",
        lambda **kwargs: _provider_result(text="\0\u200b \t\n", request_id=kwargs["request_id"]),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type == "validation_failed"
    snapshot_dir = tmp_path / response.request_id
    assert not (snapshot_dir / "dq_report.json").exists()

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["dq_status"] == "skipped"
    assert meta["dq_reasons"] == []


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
