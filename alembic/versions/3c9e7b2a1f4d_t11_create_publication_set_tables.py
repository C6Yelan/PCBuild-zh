"""t11 create publication_set tables

Revision ID: 3c9e7b2a1f4d
Revises: 8c1f4d2a9b6e
Create Date: 2026-02-28
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "3c9e7b2a1f4d"
down_revision = "8c1f4d2a9b6e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")

    op.create_table(
        "crawler_publication_set",
        sa.Column(
            "publication_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("env", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("note", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_crawler_publication_set_env_created_desc",
        "crawler_publication_set",
        ["env", sa.text("created_at DESC")],
        unique=False,
    )

    op.create_table(
        "crawler_publication_set_member",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column(
            "publication_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("crawler_publication_set.publication_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("crawler_ingest_run.run_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.UniqueConstraint("publication_id", "category", name="uq_crawler_publication_set_member_pub_cat"),
    )
    op.create_index(
        "ix_crawler_publication_set_member_category",
        "crawler_publication_set_member",
        ["category"],
        unique=False,
    )
    op.create_index(
        "ix_crawler_publication_set_member_run_id",
        "crawler_publication_set_member",
        ["run_id"],
        unique=False,
    )

    op.create_table(
        "crawler_publication_set_pointer",
        sa.Column("env", sa.Text(), primary_key=True, nullable=False),
        sa.Column(
            "publication_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("crawler_publication_set.publication_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("crawler_publication_set_pointer")

    op.drop_index("ix_crawler_publication_set_member_run_id", table_name="crawler_publication_set_member")
    op.drop_index("ix_crawler_publication_set_member_category", table_name="crawler_publication_set_member")
    op.drop_table("crawler_publication_set_member")

    op.drop_index("ix_crawler_publication_set_env_created_desc", table_name="crawler_publication_set")
    op.drop_table("crawler_publication_set")
