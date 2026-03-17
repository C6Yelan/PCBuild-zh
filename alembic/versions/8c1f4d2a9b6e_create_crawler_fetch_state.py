"""create crawler fetch state

Revision ID: 8c1f4d2a9b6e
Revises: f2b7c1d9e4a8
Create Date: 2026-02-21
"""

from alembic import op
import sqlalchemy as sa


revision = "8c1f4d2a9b6e"
down_revision = "f2b7c1d9e4a8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "crawler_fetch_state",
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("part_type", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("etag", sa.Text(), nullable=True),
        sa.Column("last_modified", sa.Text(), nullable=True),
        sa.Column("content_sha256", sa.Text(), nullable=True),
        sa.Column("last_status_code", sa.Integer(), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("source", "part_type", "url", name="pk_crawler_fetch_state"),
    )
    op.create_index(
        "ix_crawler_fetch_state_source_part",
        "crawler_fetch_state",
        ["source", "part_type"],
        unique=False,
    )
    op.create_index(
        "ix_crawler_fetch_state_updated_at",
        "crawler_fetch_state",
        ["updated_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_crawler_fetch_state_updated_at", table_name="crawler_fetch_state")
    op.drop_index("ix_crawler_fetch_state_source_part", table_name="crawler_fetch_state")
    op.drop_table("crawler_fetch_state")
