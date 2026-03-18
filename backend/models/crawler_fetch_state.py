# backend/models/crawler_fetch_state.py
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from backend.models.base import Base


class CrawlerFetchState(Base):
    """
    每個 source + part + url 的抓取狀態（供增量更新 runtime 使用）。
    """

    __tablename__ = "crawler_fetch_state"

    source: Mapped[str] = mapped_column(Text, primary_key=True, nullable=False)
    part_type: Mapped[str] = mapped_column(Text, primary_key=True, nullable=False)
    url: Mapped[str] = mapped_column(Text, primary_key=True, nullable=False)

    etag: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_modified: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_sha256: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )

    __table_args__ = (
        Index("ix_crawler_fetch_state_source_part", "source", "part_type"),
        Index("ix_crawler_fetch_state_updated_at", "updated_at"),
    )
