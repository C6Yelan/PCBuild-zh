# backend/api/routes/chat.py
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.auth import get_active_user
from backend.api.dependencies.db import get_db
from backend.core.middleware.throttling.rate_limit import limiter
from backend.models import User
from backend.schemas.chat import ChatIn, ChatOut
from backend.services.chat import generate_chat_reply

router = APIRouter(prefix="/api", tags=["chat"])


@router.post("/chat", response_model=ChatOut)
@limiter.limit("30/minute")
def chat(
    request: Request,  # SlowAPI 需要顯式 request 參數
    response: Response, # <- 新增這行（符合 SlowAPI headers_enabled=True 的要求）
    body: ChatIn,
    db: OrmSession = Depends(get_db),
    _: User = Depends(get_active_user),  # 未登入→401；未驗證→403
) -> ChatOut:
    chat_response = generate_chat_reply(chat_request=body, db=db)
    return ChatOut.model_validate(chat_response.model_dump())
