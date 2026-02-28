# backend/services/chat/context_pack/types.py
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CompressedPart(BaseModel):
    model_config = ConfigDict(extra="forbid")

    part_id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    key_specs: dict[str, object] = Field(default_factory=dict)
    price: int | None = Field(default=None, ge=0)
    source: str | None = None
    source_url: str | None = None
    snapshot_id: str | None = None
    run_id: str | None = None

    @field_validator("part_id", "category", "display_name")
    @classmethod
    def _required_text_must_not_be_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("must not be blank")
        return cleaned

    @field_validator("source", "source_url", "snapshot_id", "run_id")
    @classmethod
    def _normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


class DropLogItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    part_id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    dropped_keys: list[str] = Field(default_factory=list)
    reasons: dict[str, str] | None = None

    @field_validator("part_id", "category")
    @classmethod
    def _required_text_must_not_be_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("must not be blank")
        return cleaned
