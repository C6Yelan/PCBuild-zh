# backend/schemas/chat.py
from typing import List, Literal

from pydantic import BaseModel


class Turn(BaseModel):
    role: Literal["user", "ai"]
    content: str


class ChatIn(BaseModel):
    message: str
    history: List[Turn] = []


class ChatOut(BaseModel):
    reply: str
