from datetime import datetime

from sqlalchemy import (
    String,
    Boolean,
    DateTime,
    BigInteger,
    ForeignKey,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.models.base import Base


class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"

    # 與 users.id 對齊：BIGINT / bigserial
    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        index=True,
    )

    user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # 只存雜湊後的 token，實際 raw token 不入庫
    token_hash: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    # 區分用途：signup / login / reset_password...
    purpose: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        server_default=text("'signup'"),
    )

    # 是否已被使用（完成驗證後設為 TRUE）
    is_used: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=text("FALSE"),
    )

    # 建立時間 / 失效時間（timestamptz）
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # 關聯回 User（多對一）
    user: Mapped["User"] = relationship(
        back_populates="email_verification_tokens",
    )
