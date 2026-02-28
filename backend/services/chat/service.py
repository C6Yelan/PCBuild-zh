# backend/services/chat/service.py
from backend.schemas.chat import Turn
from backend.services.chat.clients.genai_client import get_genai_client
from backend.services.chat.prompt import build_prompt


def generate_chat_reply(message: str, history: list[Turn]) -> str:
    client = get_genai_client()
    prompt = build_prompt(message=message, history=history)
    response = client.generate_text(prompt=prompt)
    return response.text
