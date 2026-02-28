# backend/services/chat/prompt.py
from backend.schemas.chat import Turn
from backend.services.chat.config import HISTORY_MAX_TURNS, SYSTEM_PROMPT


def build_prompt(message: str, history: list[Turn]) -> str:
    def format_turn(t: Turn) -> str:
        who = "使用者" if t.role == "user" else "AI"
        return f"{who}：{t.content}"

    history_txt = "\n".join(format_turn(t) for t in history[-HISTORY_MAX_TURNS:])

    return (
        f"{SYSTEM_PROMPT}\n\n"
        f"以下是先前對話紀錄（舊→新，最多{HISTORY_MAX_TURNS}則）：\n{history_txt}\n\n"
        f"現在的使用者訊息：{message}\n"
        f"請在理解脈絡後以繁體中文回答。"
    )
