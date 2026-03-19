# backend/tests/chat/service/test_service_snapshot.py
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.service as chat_service
from backend.services.chat.context_pack.retrieval import CandidatePart, P1RetrievalResult
from backend.services.chat.contracts import ChatRequest


def _sample_candidates() -> dict[str, list[dict[str, object]]]:
    return {
        "CPU": [
            {
                "part_id": "cpu-1",
                "category": "CPU",
                "display_name": "CPU 1",
                "key_specs": {"socket_hint": "AM4"},
                "price": 1000,
                "source": "coolpc",
                "source_url": "https://example.invalid/cpu-1",
                "snapshot_id": None,
                "run_id": "run-1",
            }
        ],
        "MB": [
            {
                "part_id": "mb-1",
                "category": "MB",
                "display_name": "MB 1",
                "key_specs": {"socket_hint": "AM4"},
                "price": 2000,
                "source": "coolpc",
                "source_url": "https://example.invalid/mb-1",
                "snapshot_id": "snap-1",
                "run_id": None,
            }
        ],
    }


def _build_candidate(
    *,
    part_id: str,
    category: str,
    display_name: str,
    price: int,
    key_specs: dict[str, object],
) -> CandidatePart:
    return CandidatePart(
        part_id=part_id,
        category=category,
        display_name=display_name,
        key_specs=key_specs,
        price=price,
        source="coolpc",
        source_url=f"https://example.invalid/{part_id}",
        run_id=f"run-{part_id}",
    )


def test_snapshot_writes_extended_artifacts_with_retrieval(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir)
    compressed_candidates = _sample_candidates()
    drop_log = {
        "cpu-1": {
            "dropped_fields": [],
            "dropped_specs": [],
            "truncated_specs": {},
            "reason": ["fallback_used"],
        }
    }

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "retrieve_topk_candidates", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        chat_service,
        "compress_candidates",
        lambda *args, **kwargs: (compressed_candidates, drop_log),
    )
    monkeypatch.setattr(
        chat_service,
        "build_context_pack",
        lambda **kwargs: SimpleNamespace(text="CTX BODY", hash="ctx-hash"),
    )
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(
            request_id=kwargs["request_id"],
            text="建議選 CPU 1 搭配 MB 1，這樣的處理器與主機板組合比較穩定。",
            request_headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": "Bearer secret-value",
                "X-Client-Request-Id": kwargs["request_id"],
                "x-api-key": "top-secret",
            },
            request_json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hi"}],
                "api_key": "never-log-me",
            },
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(
        ChatRequest(
            user_text="幫我配一台文書機",
            demand={"categories": ["CPU", "MB"], "top_k": 2, "env": "prod"},
        ),
        db=object(),
    )

    snapshot_dir = snapshot_temp_dir / response.request_id
    assert (snapshot_dir / "raw_request.json").exists()
    assert (snapshot_dir / "raw_response.json").exists()
    assert (snapshot_dir / "meta.json").exists()
    assert (snapshot_dir / "context_pack.txt").exists()
    assert (snapshot_dir / "compressed_candidates.json").exists()
    assert (snapshot_dir / "drop_log.json").exists()
    assert (snapshot_dir / "request_context.json").exists()
    assert (snapshot_dir / "normalized_demand.json").exists()
    assert (snapshot_dir / "normalization_report.json").exists()
    assert (snapshot_dir / "validation_report.json").exists()
    assert (snapshot_dir / "dq_report.json").exists()
    assert (snapshot_dir / "lineage.json").exists()
    assert (snapshot_dir / "staging_record.json").exists()
    assert not (snapshot_dir / "quarantine_entry.json").exists()

    request_context = json.loads(
        (snapshot_dir / "request_context.json").read_text(encoding="utf-8")
    )
    assert request_context["demand_source"] == "explicit"
    assert request_context["triggered_retrieval"] is True
    assert request_context["categories"] == ["CPU", "MB"]
    assert request_context["top_k"] == 2
    assert request_context["env"] == "prod"
    assert request_context["has_context_pack"] is True
    assert "normalized_request_mode" in request_context

    lineage = json.loads((snapshot_dir / "lineage.json").read_text(encoding="utf-8"))
    assert lineage == {
        "request_id": response.request_id,
        "context_pack_hash": "ctx-hash",
        "categories": {
            "CPU": [
                {
                    "part_id": "cpu-1",
                    "category": "CPU",
                    "display_name": "CPU 1",
                    "source": "coolpc",
                    "source_url": "https://example.invalid/cpu-1",
                    "snapshot_id": None,
                    "run_id": "run-1",
                }
            ],
            "MB": [
                {
                    "part_id": "mb-1",
                    "category": "MB",
                    "display_name": "MB 1",
                    "source": "coolpc",
                    "source_url": "https://example.invalid/mb-1",
                    "snapshot_id": "snap-1",
                    "run_id": None,
                }
            ],
        },
    }

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["upstream_request_id"] == "up-1"
    assert meta["status_code"] == 200
    assert meta["request_mode"] == "user_text"
    assert meta["demand_source"] == "explicit"
    assert meta["triggered_retrieval"] is True
    assert meta["gate_status"] == "pass"
    assert meta["gate_reasons"] == []
    assert meta["dq_status"] == "pass"
    assert meta["dq_reasons"] == []
    assert meta["staging_status"] == "staged"
    assert meta["quarantine_status"] == "not_quarantined"
    assert meta["artifacts"] == [
        "raw_request.json",
        "raw_response.json",
        "request_context.json",
        "normalized_demand.json",
        "normalization_report.json",
        "validation_report.json",
        "dq_report.json",
        "context_pack.txt",
        "compressed_candidates.json",
        "drop_log.json",
        "lineage.json",
        "staging_record.json",
        "meta.json",
    ]
    staging_record = json.loads((snapshot_dir / "staging_record.json").read_text(encoding="utf-8"))
    assert staging_record["published"] is True
    assert staging_record["publish_blocked"] is False
    assert staging_record["publish_reason"] == "staged_pass"
    assert staging_record["data_versions"] == lineage["categories"]

    raw_request = json.loads((snapshot_dir / "raw_request.json").read_text(encoding="utf-8"))
    assert raw_request["request_headers"]["Authorization"] == "[REDACTED]"
    assert raw_request["request_headers"]["x-api-key"] == "[REDACTED]"
    assert raw_request["request_json"]["api_key"] == "[REDACTED]"


def test_snapshot_writes_minimal_artifacts_without_retrieval(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir)

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_service,
        "retrieve_topk_candidates",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("retrieval should not run")),
    )
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(request_id=kwargs["request_id"]),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=object())

    snapshot_dir = snapshot_temp_dir / response.request_id
    assert (snapshot_dir / "raw_request.json").exists()
    assert (snapshot_dir / "raw_response.json").exists()
    assert (snapshot_dir / "meta.json").exists()
    assert (snapshot_dir / "request_context.json").exists()
    assert (snapshot_dir / "normalized_demand.json").exists()
    assert (snapshot_dir / "normalization_report.json").exists()
    assert (snapshot_dir / "validation_report.json").exists()
    assert (snapshot_dir / "dq_report.json").exists()
    assert (snapshot_dir / "staging_record.json").exists()
    assert not (snapshot_dir / "quarantine_entry.json").exists()
    assert not (snapshot_dir / "context_pack.txt").exists()
    assert not (snapshot_dir / "compressed_candidates.json").exists()
    assert not (snapshot_dir / "drop_log.json").exists()
    assert not (snapshot_dir / "lineage.json").exists()

    request_context = json.loads(
        (snapshot_dir / "request_context.json").read_text(encoding="utf-8")
    )
    assert request_context["demand_source"] == "none"
    assert request_context["triggered_retrieval"] is False
    assert request_context["categories"] == []

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["gate_status"] == "pass"
    assert meta["gate_reasons"] == []
    assert meta["dq_status"] == "pass"
    assert meta["dq_reasons"] == []
    assert meta["staging_status"] == "staged"
    assert meta["quarantine_status"] == "not_quarantined"
    assert meta["artifacts"] == [
        "raw_request.json",
        "raw_response.json",
        "request_context.json",
        "normalized_demand.json",
        "normalization_report.json",
        "validation_report.json",
        "dq_report.json",
        "staging_record.json",
        "meta.json",
    ]


def test_snapshot_request_context_includes_build_scoring_summary(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir)

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(
        chat_service,
        "retrieve_topk_candidates",
        lambda *args, **kwargs: P1RetrievalResult(
            items_by_category={
                "CPU": [
                    _build_candidate(
                        part_id="cpu-mid",
                        category="CPU",
                        display_name="AMD Ryzen 5 9600X",
                        price=7600,
                        key_specs={"socket_hint": "AM5"},
                    )
                ],
                "GPU": [
                    _build_candidate(
                        part_id="gpu-mid",
                        category="GPU",
                        display_name="NVIDIA RTX 5070",
                        price=17490,
                        key_specs={"power_w_hint": 250},
                    )
                ],
                "MB": [
                    _build_candidate(
                        part_id="mb-mid",
                        category="MB",
                        display_name="B650M Gaming Plus",
                        price=4990,
                        key_specs={
                            "socket_hint": "AM5",
                            "memory_type_hint": "DDR5",
                            "chipset_hint": "B650",
                            "form_factor_hint": "M-ATX",
                        },
                    )
                ],
                "RAM": [
                    _build_candidate(
                        part_id="ram-sane",
                        category="RAM",
                        display_name="DDR5 16GBx2 Kit",
                        price=2990,
                        key_specs={"ddr_gen_hint": "DDR5", "capacity_gb_hint": 32, "kit_dimms_hint": 2},
                    )
                ],
                "SSD": [
                    _build_candidate(
                        part_id="ssd-1tb",
                        category="SSD",
                        display_name="PCIe 4.0 1TB SSD",
                        price=2290,
                        key_specs={"capacity_gib": 1000, "pcie_gen_hint": 4},
                    )
                ],
                "PSU": [
                    _build_candidate(
                        part_id="psu-650",
                        category="PSU",
                        display_name="650W Gold PSU",
                        price=2590,
                        key_specs={"wattage_w_hint": 650},
                    )
                ],
                "CASE": [
                    _build_candidate(
                        part_id="case-basic",
                        category="CASE",
                        display_name="Airflow Case",
                        price=1590,
                        key_specs={"mb_form_factor_support_hint": "ATX / M-ATX", "gpu_max_length_mm_hint": 360},
                    )
                ],
            }
        ),
    )
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(
            request_id=kwargs["request_id"],
            text="這是一組整體分配合理的 gaming build，GPU 預算配置與主機板層級都算協調。",
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(
        ChatRequest(
            user_text="幫我配一台 4 萬內遊戲機，想要 AMD CPU + NVIDIA 顯卡",
            demand={
                "categories": ["CPU", "GPU", "MB", "RAM", "SSD", "PSU", "CASE"],
                "filters": {"budget": 40000},
                "env": "prod",
            },
        ),
        db=object(),
    )

    request_context = json.loads(
        (snapshot_temp_dir / response.request_id / "request_context.json").read_text(encoding="utf-8")
    )
    scoring_summary = request_context["build_scoring_summary"]
    assert scoring_summary["usage_profile"] == "gaming"
    assert scoring_summary["target_total_price"] == 38000
    assert scoring_summary["minimum_budget_utilization"] == 36000
    assert scoring_summary["selected_build"]["parts"]["GPU"]["part_id"] == "gpu-mid"
    assert scoring_summary["selected_build"]["score_breakdown"]["motherboard_tier_match_score"] >= 80
    snapshot_dir = snapshot_temp_dir / response.request_id
    staging_record = json.loads((snapshot_dir / "staging_record.json").read_text(encoding="utf-8"))
    assert staging_record["published"] is True
    assert staging_record["publish_blocked"] is False
    assert staging_record["publish_reason"] == "staged_pass"


def test_snapshot_request_context_reflects_truncation_warning(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir, max_output_chars=5)

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(
            request_id=kwargs["request_id"],
            text="abcdefghij",
            messages=kwargs["messages"],
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(
        ChatRequest(user_text="請回一段很長的內容"),
        db=object(),
    )

    assert response.text == "abcde"
    assert response.warnings is not None
    assert "output_truncated" in response.warnings

    snapshot_dir = snapshot_temp_dir / response.request_id
    request_context = json.loads(
        (snapshot_dir / "request_context.json").read_text(encoding="utf-8")
    )
    assert "output_truncated" in request_context["warnings"]
    validation_report = json.loads(
        (snapshot_dir / "validation_report.json").read_text(encoding="utf-8")
    )
    assert validation_report["passed"] is True
    assert validation_report["reasons"] == []
    dq_report = json.loads((snapshot_dir / "dq_report.json").read_text(encoding="utf-8"))
    assert dq_report["passed"] is True
    assert dq_report["reasons"] == []
