from backend.db import engine
from backend.models.base import Base
from backend.models.user import User
from backend.models.email_verification_token import EmailVerificationToken
from backend.models.session import Session

__all__ = [
    "Base",
    "User",
    "EmailVerificationToken",
    "Session",
]

# 保留你原本的行為：import backend.models 時，若缺表就建立
# 注意：create_all 前必須先 import 完所有 models，metadata 才會齊全
Base.metadata.create_all(bind=engine)
