# app.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai
import os

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # 開發期先放寬；上線請改成你的網域
    allow_methods=["*"],
    allow_headers=["*"],
)

# 優先用環境變數；你稍後會設定 GEMINI_API_KEY/GOOGLE_API_KEY
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))

SYSTEM_PROMPT = "你是電腦組裝顧問，所有回覆一律使用繁體中文。"

class ChatIn(BaseModel):
    message: str

class ChatOut(BaseModel):
    reply: str

@app.post("/api/chat", response_model=ChatOut)
def chat(body: ChatIn):
    resp = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=f"{SYSTEM_PROMPT}\n\n使用者訊息：{body.message}"
    )
    return {"reply": resp.text}
