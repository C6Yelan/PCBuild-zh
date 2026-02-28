# backend/schemas/chat.py
from typing import List, Literal

from pydantic import BaseModel, ConfigDict, Field


class Turn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "ai"]
    content: str


class ChatIn(BaseModel):
    # provider/model/base_url/api_key 只能由後端 settings 控制，前端傳入一律拒絕。
    model_config = ConfigDict(extra="forbid")

    message: str
    history: List[Turn] = Field(default_factory=list)


class ChatOut(BaseModel):
    reply: str
