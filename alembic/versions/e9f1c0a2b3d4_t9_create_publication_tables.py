"""T9 create publication tables

Revision ID: e9f1c0a2b3d4
Revises: c4a1d2e3f4a5
Create Date: 2026-02-17
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "e9f1c0a2b3d4"
down_revision = "c4a1d2e3f4a5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 一次 publish 對應一個 ingest run（用 run_id 當 PK，避免多餘 surrogate key）
    op.create_table(
        "crawler_publication",
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("crawler_ingest_run.run_id", ondelete="RESTRICT"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("stats_json", postgresql.JSONB(), nullable=True),
    )
    op.create_index(
        "ix_crawler_publication_published_at",
        "crawler_publication",
        ["published_at"],
        unique=False,
    )

    # 指標式（env -> 當前 publication），回滾只需更新 pointer
    op.create_table(
        "crawler_publication_pointer",
        sa.Column("env", sa.Text(), primary_key=True, nullable=False),
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("crawler_publication.run_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("crawler_publication_pointer")
    op.drop_index("ix_crawler_publication_published_at", table_name="crawler_publication")
    op.drop_table("crawler_publication")
