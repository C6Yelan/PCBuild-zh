# backend/api/chat.py
from typing import List, Literal
import os

from fastapi import APIRouter
from pydantic import BaseModel
from google import genai

# 這個 router 會掛在 /api 底下
router = APIRouter(prefix="/api", tags=["chat"])

# ===== Gemini 用戶端與系統提示 =====

client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
)

SYSTEM_PROMPT = "你是電腦組裝顧問，所有回覆一律使用繁體中文。"


# ===== 多輪對話資料結構 =====

class Turn(BaseModel):
    role: Literal["user", "ai"]
    content: str


class ChatIn(BaseModel):
    message: str
    history: List[Turn] = []


class ChatOut(BaseModel):
    reply: str


# ===== /api/chat 端點 =====

@router.post("/chat", response_model=ChatOut)
def chat(body: ChatIn) -> ChatOut:
    """
    多輪對話：接收目前訊息 + 歷史紀錄，轉成文字 prompt 丟給 Gemini，再回傳單一回覆。
    """
    # 只保留最近 N 筆歷史，避免 prompt 過長
    N = 8

    def _fmt(t: Turn) -> str:
        who = "使用者" if t.role == "user" else "AI"
        return f"{who}：{t.content}"

    history_txt = "\n".join(_fmt(t) for t in body.history[-N:])

    prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"以下是先前對話紀錄（舊→新，最多{N}則）：\n{history_txt}\n\n"
        f"現在的使用者訊息：{body.message}\n"
        f"請在理解脈絡後以繁體中文回答。"
    )

    resp = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
    )

    reply_text = (resp.text or "").strip()
    return ChatOut(reply=reply_text)
