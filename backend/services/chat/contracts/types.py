# backend/services/chat/contracts/types.py
from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class ContextPart(BaseModel):
    model_config = ConfigDict(extra="forbid")

    part_id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    key_specs: dict[str, Any] = Field(default_factory=dict)
    price: float | None = Field(default=None, ge=0)
    source: str = Field(min_length=1)
    source_url: HttpUrl
    snapshot_id: str | None = None
    run_id: str | None = None

    @field_validator("part_id", "category", "display_name", "source")
    @classmethod
    def _required_text_must_not_be_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("must not be blank")
        return cleaned

    @field_validator("snapshot_id", "run_id")
    @classmethod
    def _normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


class ChatResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: UUID
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    text: str = Field(min_length=1)
    latency_ms: int = Field(ge=0)
    error_type: str | None = None

    @field_validator("provider", "model", "text")
    @classmethod
    def _text_must_not_be_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("must not be blank")
        return cleaned

    @field_validator("error_type")
    @classmethod
    def _normalize_error_type(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


class P1Demand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    budget: int | None = Field(default=None, ge=0)
    keyword: str | None = None

    @field_validator("keyword")
    @classmethod
    def _normalize_keyword(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


class PartCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    part_id: UUID
    category: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    key_specs: dict[str, str] = Field(default_factory=dict)
    price: int | None = Field(default=None, ge=0)
    currency: str | None = None
    source: str = Field(min_length=1)
    source_url: str = Field(min_length=1)
    snapshot_id: UUID | None = None

    @field_validator("category", "display_name", "source", "source_url")
    @classmethod
    def _required_candidate_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("must not be blank")
        return cleaned

    @field_validator("currency")
    @classmethod
    def _normalize_currency(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


class RetrievalLogItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str = Field(min_length=1)
    filters: list[str] = Field(default_factory=list)
    order_by: list[str] = Field(default_factory=list)
    matched_count: int = Field(ge=0)
    returned_count: int = Field(ge=0)
    top_k: int = Field(ge=1)
    snapshot_id: UUID | None = None

    @field_validator("category")
    @classmethod
    def _required_category(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("must not be blank")
        return cleaned


class P1RetrievalResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: UUID | None = None
    candidates: dict[str, list[PartCandidate]] = Field(default_factory=dict)
    retrieval_log: list[RetrievalLogItem] = Field(default_factory=list)
