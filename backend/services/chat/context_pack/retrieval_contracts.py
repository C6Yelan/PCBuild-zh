# backend/services/chat/context_pack/retrieval_contracts.py
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class P1Demand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    budget: int | None = Field(default=None, ge=0)
    target_price: int | None = Field(default=None, ge=0)
    min_price: int | None = Field(default=None, ge=0)
    max_price: int | None = Field(default=None, ge=0)

    @model_validator(mode="before")
    @classmethod
    def _normalize_budget_aliases(cls, raw: Any) -> Any:
        if not isinstance(raw, dict):
            return raw
        normalized = dict(raw)
        if normalized.get("max_price") is None and normalized.get("budget") is not None:
            normalized["max_price"] = normalized["budget"]
        return normalized

    @model_validator(mode="after")
    def _validate_price_range(self) -> "P1Demand":
        if self.min_price is not None and self.max_price is not None and self.min_price > self.max_price:
            raise ValueError("min_price must be <= max_price")
        return self


class CandidatePart(BaseModel):
    model_config = ConfigDict(extra="forbid")

    part_id: str
    category: str
    display_name: str
    key_specs: dict[str, Any]
    price: int | None = None
    source: str
    source_url: str
    snapshot_id: str | None = None
    run_id: str | None = None

    @model_validator(mode="after")
    def _validate_lineage(self) -> "CandidatePart":
        if self.snapshot_id or self.run_id:
            return self
        raise ValueError("CandidatePart requires snapshot_id or run_id")


class P1RetrievalResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items_by_category: dict[str, list[CandidatePart]]
