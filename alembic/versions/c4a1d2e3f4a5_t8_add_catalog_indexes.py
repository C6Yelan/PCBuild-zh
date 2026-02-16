"""t8 add catalog indexes

Revision ID: c4a1d2e3f4a5
Revises: b8f2c9a0d7e1
Create Date: 2026-02-17
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "c4a1d2e3f4a5"
down_revision = "b8f2c9a0d7e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # trigram 索引需要 pg_trgm
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")

    # Postgres: CREATE INDEX CONCURRENTLY 不能在 transaction block 內跑
    # Alembic 用 autocommit_block 來處理這種情境
    ctx = op.get_context()
    with ctx.autocommit_block():
        # 1) 列表頁：category + updated_at DESC
        op.execute(
            """
            CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_catalog_product_category_updated_desc
            ON public.catalog_product (category, updated_at DESC);
            """
        )

        # 2) 取最新價格： (product_id, captured_at DESC) + INCLUDE (price, currency)
        op.execute(
            """
            CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_catalog_price_snapshot_pid_captured_desc_inc
            ON public.catalog_price_snapshot (product_id, captured_at DESC)
            INCLUDE (price, currency);
            """
        )

        # 3) 模糊搜尋：title / sku_hint trigram
        op.execute(
            """
            CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_catalog_product_title_trgm
            ON public.catalog_product
            USING gin (title gin_trgm_ops);
            """
        )
        op.execute(
            """
            CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_catalog_product_sku_trgm
            ON public.catalog_product
            USING gin (sku_hint gin_trgm_ops);
            """
        )

        # 4) 你之前建立後又刪掉的舊索引（保險起見，存在就順手清掉）
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.ix_catalog_price_snapshot_pid_captured_desc;")


def downgrade() -> None:
    ctx = op.get_context()
    with ctx.autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.ix_catalog_product_sku_trgm;")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.ix_catalog_product_title_trgm;")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.ix_catalog_price_snapshot_pid_captured_desc_inc;")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.ix_catalog_product_category_updated_desc;")

    # extension 是否要在 downgrade 移除：通常不強求（若你確定只有這裡用到才刪）
    # op.execute("DROP EXTENSION IF EXISTS pg_trgm;")
