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


class CrawlerPublicationSet(Base):
    """
    publication set：同一 env 的一組 category -> run_id 發佈快照。
    """

    __tablename__ = "crawler_publication_set"
    __table_args__ = (
        sa.Index(
            "ix_crawler_publication_set_env_created_desc",
            "env",
            sa.text("created_at DESC"),
        ),
    )

    publication_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        nullable=False,
        server_default=sa.text("gen_random_uuid()"),
    )
    env: Mapped[str] = mapped_column(sa.Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )
    note: Mapped[str | None] = mapped_column(sa.Text, nullable=True)


class CrawlerPublicationSetMember(Base):
    """
    publication set member：publication_id 底下每個 category 指向一個 run_id。
    """

    __tablename__ = "crawler_publication_set_member"
    __table_args__ = (
        sa.UniqueConstraint("publication_id", "category", name="uq_crawler_publication_set_member_pub_cat"),
        sa.Index("ix_crawler_publication_set_member_category", "category"),
        sa.Index("ix_crawler_publication_set_member_run_id", "run_id"),
    )

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    publication_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        sa.ForeignKey("crawler_publication_set.publication_id", ondelete="CASCADE"),
        nullable=False,
    )
    category: Mapped[str] = mapped_column(sa.Text, nullable=False)
    run_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        sa.ForeignKey("crawler_ingest_run.run_id", ondelete="RESTRICT"),
        nullable=False,
    )


class CrawlerPublicationSetPointer(Base):
    """
    新 pointer：env -> current publication_set_id。
    """

    __tablename__ = "crawler_publication_set_pointer"

    env: Mapped[str] = mapped_column(sa.Text, primary_key=True, nullable=False)
    publication_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        sa.ForeignKey("crawler_publication_set.publication_id", ondelete="RESTRICT"),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )
