"""t7_create_staging_tables

Revision ID: 7740451cb110
Revises: d6e0a1a18b73
Create Date: 2026-02-15 13:20:39.543792

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '7740451cb110'
down_revision: Union[str, Sequence[str], None] = 'd6e0a1a18b73'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1) 每次入庫/跑批一筆
    op.create_table(
        "crawler_ingest_run",
        sa.Column("run_id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("note", sa.Text(), nullable=True),
    )

    # 2) staging item：每個商品一筆（run_id + item_key 當主鍵）
    op.create_table(
        "crawler_stg_item",
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("crawler_ingest_run.run_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("item_key", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("price", sa.Integer(), nullable=False),
        sa.Column("currency", sa.Text(), nullable=False),
        sa.Column("sku_hint", sa.Text(), nullable=True),
        sa.Column("canonical_json", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("price >= 0", name="ck_crawler_stg_item_price_nonneg"),
        sa.PrimaryKeyConstraint("run_id", "item_key", name="pk_crawler_stg_item"),
    )
    op.create_index("ix_crawler_stg_item_run_category", "crawler_stg_item", ["run_id", "category"])
    op.create_index("ix_crawler_stg_item_url", "crawler_stg_item", ["url"])

    # 3) gate 結果：每個商品每個 gate 一筆（3NF：結果獨立於 item）
    op.create_table(
        "crawler_stg_gate_result",
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("item_key", sa.Text(), nullable=False),
        sa.Column("gate_name", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),  # 'pass' / 'fail'
        sa.Column("detail_json", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("status in ('pass','fail')", name="ck_crawler_stg_gate_result_status"),
        sa.ForeignKeyConstraint(
            ["run_id", "item_key"],
            ["crawler_stg_item.run_id", "crawler_stg_item.item_key"],
            ondelete="CASCADE",
            name="fk_crawler_stg_gate_result_item",
        ),
        sa.PrimaryKeyConstraint("run_id", "item_key", "gate_name", name="pk_crawler_stg_gate_result"),
    )
    op.create_index(
        "ix_crawler_stg_gate_result_gate_status",
        "crawler_stg_gate_result",
        ["gate_name", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_crawler_stg_gate_result_gate_status", table_name="crawler_stg_gate_result")
    op.drop_table("crawler_stg_gate_result")

    op.drop_index("ix_crawler_stg_item_url", table_name="crawler_stg_item")
    op.drop_index("ix_crawler_stg_item_run_category", table_name="crawler_stg_item")
    op.drop_table("crawler_stg_item")

    op.drop_table("crawler_ingest_run")

