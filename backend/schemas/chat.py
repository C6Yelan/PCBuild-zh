# backend/schemas/chat.py
from pydantic import AliasChoices, ConfigDict, Field

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


class ChatOut(ChatResponse):
    pass
