# backend/services/chat/contracts/types.py
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


SpecValue = str | int | float | bool | None
ChatRole = Literal["system", "user", "assistant", "ai"]


class ChatMessage(BaseModel):
    role: ChatRole
    content: str


class ContextPackItem(BaseModel):
    part_id: str
    category: str
    display_name: str
    key_specs: dict[str, SpecValue]
    price: float | None = None
    source: str
    source_url: str
    snapshot_id: str | None = None
    run_id: str | None = None

    @model_validator(mode="after")
    def _validate_lineage(self) -> "ContextPackItem":
        if self.snapshot_id or self.run_id:
            return self
        raise ValueError("ContextPackItem requires snapshot_id or run_id")


class ContextPack(BaseModel):
    items: list[ContextPackItem]
    context_pack_hash: str | None = None


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    messages: list[ChatMessage] | None = None
    user_text: str | None = None
    history: list[ChatMessage] = Field(default_factory=list)
    demand: dict[str, Any] | str | None = None
    context_pack: ContextPack | None = None

    @model_validator(mode="after")
    def _validate_input_modes(self) -> "ChatRequest":
        if self.messages:
            return self
        if self.user_text and self.user_text.strip():
            return self
        raise ValueError("ChatRequest requires messages or user_text")


class ChatResponse(BaseModel):
    request_id: str
    provider: str
    model: str
    text: str
    latency_ms: int
    error_type: str | None = None
    warnings: list[str] | None = None
    compressed_candidates: dict[str, list[ContextPackItem]] | None = None
    drop_log: dict[str, dict[str, Any]] | None = None
