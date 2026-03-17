# backend/models/session.py
from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Text,
    Boolean,
    DateTime,
    BigInteger,
    ForeignKey,
    Index,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.models.base import Base


class Session(Base):
    __tablename__ = "sessions"

    # 對齊既有 DB 的 index 名稱，避免 baseline 生成 drop_index
    __table_args__ = (
        Index("idx_sessions_user_id", "user_id"),
        Index("idx_sessions_expires_at", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
    )
    user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("NOW()"),
        nullable=False,
    )
    # 對齊既有 DB：TEXT（若你未來要做長度限制，再用 migrations 改成 VARCHAR(16)）
    kind: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default=text("'login'"),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    revoked: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=text("FALSE"),
    )

    user: Mapped["User"] = relationship(back_populates="sessions")
