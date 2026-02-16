# backend/models/catalog.py
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
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.models.base import Base


class CatalogSource(Base):
    """
    資料來源維度表（例如 coolpc / official / ...）
    """
    __tablename__ = "catalog_source"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(Text, nullable=False, unique=True)  # e.g. "coolpc"
    name: Mapped[str] = mapped_column(Text, nullable=False)               # 顯示名稱
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )

    products: Mapped[list["CatalogProduct"]] = relationship(back_populates="source")


class CatalogBrand(Base):
    """
    品牌維度表（可先允許 product.brand_id 為 NULL，後續再補品牌萃取/對照）
    """
    __tablename__ = "catalog_brand"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )

    products: Mapped[list["CatalogProduct"]] = relationship(back_populates="brand")


class CatalogProduct(Base):
    """
    產品主檔（以 source + source_item_key 做唯一鍵，先做到「同一來源不重複」）
    """
    __tablename__ = "catalog_product"

    product_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)

    source_id: Mapped[int] = mapped_column(
        ForeignKey("catalog_source.id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_item_key: Mapped[str] = mapped_column(Text, nullable=False)  # 對應 staging.item_key

    category: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    sku_hint: Mapped[str | None] = mapped_column(Text, nullable=True)

    brand_id: Mapped[int | None] = mapped_column(
        ForeignKey("catalog_brand.id", ondelete="SET NULL"),
        nullable=True,
    )

    # lineage：可追溯到哪一次 ingest run 第一次/最後一次看到
    first_seen_run_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("crawler_ingest_run.run_id", ondelete="SET NULL"),
        nullable=True,
    )
    last_seen_run_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("crawler_ingest_run.run_id", ondelete="SET NULL"),
        nullable=True,
    )

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
        UniqueConstraint("source_id", "source_item_key", name="uq_catalog_product_source_item_key"),
        Index("ix_catalog_product_category", "category"),
        Index("ix_catalog_product_url", "url"),
        Index("ix_catalog_product_sku_hint", "sku_hint"),
    )

    source: Mapped["CatalogSource"] = relationship(back_populates="products")
    brand: Mapped["CatalogBrand | None"] = relationship(back_populates="products")

    price_snapshots: Mapped[list["CatalogPriceSnapshot"]] = relationship(
        back_populates="product",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    specs: Mapped[list["CatalogProductSpec"]] = relationship(
        back_populates="product",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class CatalogPriceSnapshot(Base):
    """
    價格事實表（保留歷史）：同一個 product 在同一個 run_id 只寫一筆
    """
    __tablename__ = "catalog_price_snapshot"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    product_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("catalog_product.product_id", ondelete="CASCADE"),
        nullable=False,
    )
    run_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("crawler_ingest_run.run_id", ondelete="CASCADE"),
        nullable=False,
    )

    price: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(Text, nullable=False)

    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )

    __table_args__ = (
        CheckConstraint("price >= 0", name="ck_catalog_price_snapshot_price_nonneg"),
        UniqueConstraint("product_id", "run_id", name="uq_catalog_price_snapshot_product_run"),
        Index("ix_catalog_price_snapshot_run", "run_id"),
        Index("ix_catalog_price_snapshot_product", "product_id"),
    )

    product: Mapped["CatalogProduct"] = relationship(back_populates="price_snapshots")


class CatalogSpecKey(Base):
    """
    規格 key 字典表，避免 key 重複、利於索引與一致化
    """
    __tablename__ = "catalog_spec_key"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)  # e.g. "socket", "watt", "pcie_gen"
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )


class CatalogProductSpec(Base):
    """
    產品規格（key-value），以 product + spec_key 唯一
    """
    __tablename__ = "catalog_product_spec"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    product_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("catalog_product.product_id", ondelete="CASCADE"),
        nullable=False,
    )
    spec_key_id: Mapped[int] = mapped_column(
        ForeignKey("catalog_spec_key.id", ondelete="RESTRICT"),
        nullable=False,
    )

    value_text: Mapped[str] = mapped_column(Text, nullable=False)
    unit: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("product_id", "spec_key_id", name="uq_catalog_product_spec_product_key"),
        Index("ix_catalog_product_spec_product", "product_id"),
        Index("ix_catalog_product_spec_key", "spec_key_id"),
    )

    product: Mapped["CatalogProduct"] = relationship(back_populates="specs")
