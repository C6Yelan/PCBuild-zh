# backend/schemas/chat.py
from typing import Any

from pydantic import AliasChoices, ConfigDict, Field, model_validator

from backend.services.chat.contracts import ChatMessage, ChatRequest, ChatResponse


class Turn(ChatMessage):
    pass


class ChatIn(ChatRequest):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    user_text: str | None = Field(
        default=None,
        validation_alias=AliasChoices("user_text", "message"),
        serialization_alias="user_text",
    )
    messages: list[Turn] | None = None
    history: list[Turn] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _forbid_provider_overrides(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value

        blocked_keys = {"provider", "model", "base_url", "api_key"}
        incoming_keys = {str(key).strip().lower() for key in value.keys()}
        blocked = sorted(incoming_keys & blocked_keys)
        if blocked:
            blocked_display = ", ".join(blocked)
            raise ValueError(f"ChatIn does not allow override fields: {blocked_display}")
        return value


class ChatOut(ChatResponse):
    pass
