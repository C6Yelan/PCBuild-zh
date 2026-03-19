from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend.core.settings import Settings
from backend.services.chat.context_pack import P1Demand
from backend.services.chat.context_pack.typesense_adapter import (
    TypesenseCategorySearchResult,
    TypesenseConfigurationError,
    build_typesense_search_params,
)
from backend.services.chat.context_pack import retrieval_runtime
from backend.services.chat.context_pack.retrieval_contracts import CandidatePart


def test_settings_parse_typesense_env_defaults_to_disabled() -> None:
    settings = Settings(
        _env_file=None,
        DATABASE_URL="postgresql+psycopg2://pcbuild:pw@localhost:5432/pcbuild",
    )

    assert settings.typesense_enabled is False
    assert settings.typesense_host == "typesense"
    assert settings.typesense_port == 8108
    assert settings.typesense_protocol == "http"
    assert settings.typesense_collection_parts == "parts"
    assert settings.typesense_timeout_seconds == 2.0
    assert settings.get_typesense_api_key() is None


def test_settings_parse_typesense_secret_and_base_url() -> None:
    settings = Settings(
        _env_file=None,
        DATABASE_URL="postgresql+psycopg2://pcbuild:pw@localhost:5432/pcbuild",
        TYPESENSE_ENABLED=True,
        TYPESENSE_HOST="search.internal",
        TYPESENSE_PORT=9443,
        TYPESENSE_PROTOCOL="https",
        TYPESENSE_API_KEY="top-secret",
        TYPESENSE_COLLECTION_PARTS="parts_v1",
        TYPESENSE_TIMEOUT_SECONDS=4.5,
    )

    assert settings.typesense_enabled is True
    assert settings.get_typesense_api_key() == "top-secret"
    assert settings.typesense_base_url() == "https://search.internal:9443"


def test_build_typesense_search_params_maps_filters_and_top_k() -> None:
    params = build_typesense_search_params(
        env="prod",
        category="GPU",
        top_k=7,
        demand=P1Demand(query_text="RTX 5070", budget=20000, min_price=15000),
    )

    assert params["q"] == "RTX 5070"
    assert params["query_by"] == "searchable_text,title,model,brand,sku"
    assert params["query_by_weights"] == "6,5,4,3,2"
    assert params["filter_by"] == 'env:="prod" && category:="GPU" && available:=true && price_twd:>=15000 && price_twd:<=20000'
    assert params["sort_by"] == "_text_match:desc,price_twd:asc,part_id:asc"
    assert params["per_page"] == "7"


def test_build_typesense_search_params_uses_star_when_query_absent() -> None:
    params = build_typesense_search_params(
        env="prod",
        category="CPU",
        top_k=3,
        demand=P1Demand(max_price=12000),
    )

    assert params["q"] == "*"
    assert params["sort_by"] == "price_twd:asc,part_id:asc"
    assert params["filter_by"] == 'env:="prod" && category:="CPU" && available:=true && price_twd:<=12000'


class _FallbackDB:
    def get(self, model: object, key: object) -> object:
        return SimpleNamespace(run_id="publication-run-1")


def test_retrieve_topk_candidates_falls_back_to_postgresql_when_typesense_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, dict[str, object]]] = []
    candidate = CandidatePart(
        part_id="gpu-1",
        category="GPU",
        display_name="RTX 5070",
        key_specs={"vram_gb_hint": 12},
        price=19990,
        source="coolpc",
        source_url="https://example.invalid/gpu-1",
        run_id="run-gpu-1",
    )

    monkeypatch.setattr(
        retrieval_runtime,
        "get_settings",
        lambda: SimpleNamespace(typesense_enabled=True),
    )
    monkeypatch.setattr(
        retrieval_runtime,
        "search_parts_typesense",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            TypesenseConfigurationError("Typesense is enabled but missing config")
        ),
    )
    monkeypatch.setattr(
        retrieval_runtime,
        "fetch_category_candidates",
        lambda *args, **kwargs: (5, [candidate]),
    )
    monkeypatch.setattr(
        retrieval_runtime,
        "detect_pg_trgm_support",
        lambda db: False,
    )
    monkeypatch.setattr(
        retrieval_runtime,
        "log_operation",
        lambda event, **fields: events.append((event, fields)),
    )

    result = retrieval_runtime.retrieve_topk_candidates(
        _FallbackDB(),
        categories=["GPU"],
        top_k=4,
        demand=P1Demand(query_text="RTX 5070", budget=20000),
        env="prod",
    )

    assert result.items_by_category["GPU"] == [candidate]
    assert [event for event, _ in events] == ["p1_retrieval_fallback", "p1_retrieval"]
    assert events[0][1]["retrieval_backend"] == "typesense"
    assert events[0][1]["fallback_backend"] == "postgresql"
    assert events[1][1]["retrieval_backend"] == "postgresql"
    assert events[1][1]["fallback_used"] is True


def test_retrieve_topk_candidates_prefers_typesense_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, dict[str, object]]] = []
    candidate = CandidatePart(
        part_id="cpu-1",
        category="CPU",
        display_name="Ryzen 7 9700X",
        key_specs={"socket": "AM5"},
        price=10990,
        source="coolpc",
        source_url="https://example.invalid/cpu-1",
        run_id="run-cpu-1",
    )

    monkeypatch.setattr(
        retrieval_runtime,
        "get_settings",
        lambda: SimpleNamespace(typesense_enabled=True),
    )
    monkeypatch.setattr(
        retrieval_runtime,
        "search_parts_typesense",
        lambda *args, **kwargs: {
            "CPU": TypesenseCategorySearchResult(found=12, candidates=[candidate]),
        },
    )
    monkeypatch.setattr(
        retrieval_runtime,
        "fetch_category_candidates",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("pg fallback should not run")),
    )
    monkeypatch.setattr(
        retrieval_runtime,
        "log_operation",
        lambda event, **fields: events.append((event, fields)),
    )

    result = retrieval_runtime.retrieve_topk_candidates(
        _FallbackDB(),
        categories=["CPU"],
        top_k=5,
        demand=P1Demand(query_text="Ryzen 9700X"),
        env="prod",
    )

    assert result.items_by_category["CPU"] == [candidate]
    assert len(events) == 1
    assert events[0][0] == "p1_retrieval"
    assert events[0][1]["retrieval_backend"] == "typesense"
    assert events[0][1]["fallback_used"] is False
