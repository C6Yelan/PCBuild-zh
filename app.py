# app.py
from fastapi.responses import FileResponse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai
from fastapi.staticfiles import StaticFiles   # 新增
import os

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 原本的 home() 請移除或註解掉
# @app.get("/", include_in_schema=False)
# def home():
#     return FileResponse("index.html")

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

# 用靜態站台方式提供 index.html 與前端資源
app.mount("/", StaticFiles(directory=".", html=True), name="site")  # 新增
