"""baseline

這支檔案是為了修復 alembic 檔案被清掉後，讓既有資料庫的 alembic_version
仍能對應到 revision 'd6e0a1a18b73'。

注意：此 baseline 不包含 create table；若要重建全新資料庫，應改用
alembic revision --autogenerate 產生真正的初始 migration。
"""

from __future__ import annotations

from alembic import op  # noqa: F401
import sqlalchemy as sa  # noqa: F401

revision = "d6e0a1a18b73"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 既有 DB 會因為 alembic_version 已是此 revision 而不會重跑
    pass


def downgrade() -> None:
    pass
