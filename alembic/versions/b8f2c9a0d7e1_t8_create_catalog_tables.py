"""T8 create catalog tables

Revision ID: b8f2c9a0d7e1
Revises: 7740451cb110
Create Date: 2026-02-17
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "b8f2c9a0d7e1"
down_revision = "7740451cb110"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # catalog_source
    op.create_table(
        "catalog_source",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("code", name="uq_catalog_source_code"),
    )

    # catalog_brand
    op.create_table(
        "catalog_brand",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("name", name="uq_catalog_brand_name"),
    )

    # catalog_spec_key
    op.create_table(
        "catalog_spec_key",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("key", name="uq_catalog_spec_key_key"),
    )

    # catalog_product
    op.create_table(
        "catalog_product",
        sa.Column("product_id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("catalog_source.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("source_item_key", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("sku_hint", sa.Text(), nullable=True),
        sa.Column("brand_id", sa.Integer(), sa.ForeignKey("catalog_brand.id", ondelete="SET NULL"), nullable=True),
        sa.Column(
            "first_seen_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("crawler_ingest_run.run_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "last_seen_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("crawler_ingest_run.run_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("source_id", "source_item_key", name="uq_catalog_product_source_item_key"),
    )
    op.create_index("ix_catalog_product_category", "catalog_product", ["category"])
    op.create_index("ix_catalog_product_url", "catalog_product", ["url"])
    op.create_index("ix_catalog_product_sku_hint", "catalog_product", ["sku_hint"])

    # catalog_price_snapshot
    op.create_table(
        "catalog_price_snapshot",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "product_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("catalog_product.product_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("crawler_ingest_run.run_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("price", sa.Integer(), nullable=False),
        sa.Column("currency", sa.Text(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("price >= 0", name="ck_catalog_price_snapshot_price_nonneg"),
        sa.UniqueConstraint("product_id", "run_id", name="uq_catalog_price_snapshot_product_run"),
    )
    op.create_index("ix_catalog_price_snapshot_run", "catalog_price_snapshot", ["run_id"])
    op.create_index("ix_catalog_price_snapshot_product", "catalog_price_snapshot", ["product_id"])

    # catalog_product_spec
    op.create_table(
        "catalog_product_spec",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "product_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("catalog_product.product_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "spec_key_id",
            sa.Integer(),
            sa.ForeignKey("catalog_spec_key.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("value_text", sa.Text(), nullable=False),
        sa.Column("unit", sa.Text(), nullable=True),
        sa.UniqueConstraint("product_id", "spec_key_id", name="uq_catalog_product_spec_product_key"),
    )
    op.create_index("ix_catalog_product_spec_product", "catalog_product_spec", ["product_id"])
    op.create_index("ix_catalog_product_spec_key", "catalog_product_spec", ["spec_key_id"])


def downgrade() -> None:
    op.drop_index("ix_catalog_product_spec_key", table_name="catalog_product_spec")
    op.drop_index("ix_catalog_product_spec_product", table_name="catalog_product_spec")
    op.drop_table("catalog_product_spec")

    op.drop_index("ix_catalog_price_snapshot_product", table_name="catalog_price_snapshot")
    op.drop_index("ix_catalog_price_snapshot_run", table_name="catalog_price_snapshot")
    op.drop_table("catalog_price_snapshot")

    op.drop_index("ix_catalog_product_sku_hint", table_name="catalog_product")
    op.drop_index("ix_catalog_product_url", table_name="catalog_product")
    op.drop_index("ix_catalog_product_category", table_name="catalog_product")
    op.drop_table("catalog_product")

    op.drop_table("catalog_spec_key")
    op.drop_table("catalog_brand")
    op.drop_table("catalog_source")
