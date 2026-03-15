from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend.services.chat.context_pack import retrieve_topk_candidates
from backend.services.chat.context_pack.retrieval import P1Demand, P1_ORDER_BY
from backend.services.chat.context_pack import retrieval_runtime


class _FakeExecuteResult:
    def __init__(self, *, scalar: int | None = None, rows: list[dict[str, object]] | None = None) -> None:
        self._scalar = scalar
        self._rows = rows or []

    def scalar_one(self) -> int:
        assert self._scalar is not None
        return self._scalar

    def mappings(self):
        return iter(self._rows)


class _FakeDB:
    def __init__(self) -> None:
        self._execute_count = 0

    def get(self, model: object, key: object) -> object:
        return SimpleNamespace(run_id="publication-run-1")

    def execute(self, stmt: object) -> _FakeExecuteResult:
        self._execute_count += 1
        if self._execute_count == 1:
            return _FakeExecuteResult(scalar=3)
        return _FakeExecuteResult(
            rows=[
                {
                    "part_id": "cpu-1",
                    "category": "CPU",
                    "display_name": "Ryzen 7 7700",
                    "key_specs": {"socket": "AM5"},
                    "price": 8990,
                    "source": "coolpc",
                    "source_url": "https://example.invalid/cpu-1",
                    "item_run_id": "run-cpu-1",
                },
                {
                    "part_id": "cpu-2",
                    "category": "CPU",
                    "display_name": "Ryzen 7 9700X",
                    "key_specs": {"socket": "AM5"},
                    "price": 10990,
                    "source": "coolpc",
                    "source_url": "https://example.invalid/cpu-2",
                    "item_run_id": "run-cpu-2",
                },
            ]
        )


class _MissingPointerDB:
    def get(self, model: object, key: object) -> object | None:
        return None


def test_retrieve_topk_candidates_normalizes_inputs_and_logs(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        retrieval_runtime,
        "log_operation",
        lambda event, **fields: events.append((event, fields)),
    )

    result = retrieve_topk_candidates(
        _FakeDB(),
        categories=["CPU", "CPU", "  "],
        top_k=1,
        demand=P1Demand(min_price=1000),
        env="prod",
    )

    assert list(result.items_by_category.keys()) == ["CPU"]
    assert len(result.items_by_category["CPU"]) == 1
    assert result.items_by_category["CPU"][0].model_dump() == {
        "part_id": "cpu-1",
        "category": "CPU",
        "display_name": "Ryzen 7 7700",
        "key_specs": {"socket": "AM5"},
        "price": 8990,
        "source": "coolpc",
        "source_url": "https://example.invalid/cpu-1",
        "snapshot_id": None,
        "run_id": "run-cpu-1",
    }
    assert len(events) == 1
    event, fields = events[0]
    assert event == "p1_retrieval"
    assert fields["part_category"] == "CPU"
    assert fields["env"] == "prod"
    assert fields["publication_run_id"] == "publication-run-1"
    assert fields["top_k"] == 1
    assert fields["matched_count"] == 3
    assert fields["returned_count"] == 1
    assert fields["order_by"] == P1_ORDER_BY
    assert fields["filters"] == "min_price>=1000"
    assert isinstance(fields["latency_ms"], int)
    assert fields["latency_ms"] >= 0


def test_retrieve_topk_candidates_requires_publication_pointer() -> None:
    with pytest.raises(RuntimeError, match="please publish first"):
        retrieve_topk_candidates(
            _MissingPointerDB(),
            categories=["CPU"],
            top_k=1,
            env="prod",
        )
