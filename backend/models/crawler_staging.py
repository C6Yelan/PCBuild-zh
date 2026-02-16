# backend/models/crawler_staging.py
from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Text,
    Integer,
    DateTime,
    ForeignKey,
    CheckConstraint,
    Index,
    ForeignKeyConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.models.base import Base


class CrawlerIngestRun(Base): # 對應一次 crawler 執行，可能包含多個 item
    __tablename__ = "crawler_ingest_run"

    run_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    items: Mapped[list["CrawlerStgItem"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class CrawlerStgItem(Base): # crawler 執行中每個被抓到的 item，gate result 會對應到這邊
    __tablename__ = "crawler_stg_item"

    run_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("crawler_ingest_run.run_id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    item_key: Mapped[str] = mapped_column(Text, primary_key=True, nullable=False)

    category: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    price: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(Text, nullable=False)
    sku_hint: Mapped[str | None] = mapped_column(Text, nullable=True)

    canonical_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))

    __table_args__ = (
        # 對齊 DB 既有 constraint / index 名稱，避免未來 baseline 噪音
        CheckConstraint("price >= 0", name="ck_crawler_stg_item_price_nonneg"),
        Index("ix_crawler_stg_item_run_category", "run_id", "category"),
        Index("ix_crawler_stg_item_url", "url"),
    )

    run: Mapped["CrawlerIngestRun"] = relationship(back_populates="items")

    gate_results: Mapped[list["CrawlerStgGateResult"]] = relationship(
        back_populates="item",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class CrawlerStgGateResult(Base): # 每個 gate 的結果，對應到 crawler_stg_item 的 run_id + item_key
    __tablename__ = "crawler_stg_gate_result"

    run_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, nullable=False)
    item_key: Mapped[str] = mapped_column(Text, primary_key=True, nullable=False)
    gate_name: Mapped[str] = mapped_column(Text, primary_key=True, nullable=False)

    status: Mapped[str] = mapped_column(Text, nullable=False)  # pass / fail
    detail_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))

    __table_args__ = (
        CheckConstraint("status in ('pass','fail')", name="ck_crawler_stg_gate_result_status"),
        ForeignKeyConstraint(
            ["run_id", "item_key"],
            ["crawler_stg_item.run_id", "crawler_stg_item.item_key"],
            ondelete="CASCADE",
            name="fk_crawler_stg_gate_result_item",
        ),
        Index("ix_crawler_stg_gate_result_gate_status", "gate_name", "status"),
    )

    item: Mapped["CrawlerStgItem"] = relationship(back_populates="gate_results")
