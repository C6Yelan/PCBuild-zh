# backend/models/crawler_publication.py
from __future__ import annotations

from datetime import datetime
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.models.base import Base


class CrawlerPublication(Base):
    """
    一次 publish 對應一個 ingest run（PK = run_id）
    DB 端已有 published_at 的 server default（migration 設定），ORM 也標記 server_default 以符合 DB 行為。
    """
    __tablename__ = "crawler_publication"

    run_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        sa.ForeignKey("crawler_ingest_run.run_id", ondelete="RESTRICT"),
        primary_key=True,
        nullable=False,
    )
    published_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )
    note: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    stats_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)


class CrawlerPublicationPointer(Base):
    """
    指標式：env -> current published run_id
    回滾只需更新這張表即可。
    """
    __tablename__ = "crawler_publication_pointer"

    env: Mapped[str] = mapped_column(sa.Text, primary_key=True, nullable=False)
    run_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        sa.ForeignKey("crawler_publication.run_id", ondelete="RESTRICT"),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )
