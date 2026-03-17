"""create catalog views

Revision ID: f2b7c1d9e4a8
Revises: e9f1c0a2b3d4
Create Date: 2026-02-20
"""

from alembic import op


revision = "f2b7c1d9e4a8"
down_revision = "e9f1c0a2b3d4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE VIEW v_catalog_product_specs_json AS
        SELECT
          ps.product_id,
          jsonb_object_agg(
            sk.key,
            jsonb_build_object('value', ps.value_text, 'unit', NULLIF(ps.unit,''))
          ) AS specs
        FROM catalog_product_spec ps
        JOIN catalog_spec_key sk ON sk.id = ps.spec_key_id
        GROUP BY ps.product_id;
        """
    )

    op.execute(
        """
        CREATE OR REPLACE VIEW v_catalog_product_with_specs AS
        SELECT
          p.*,
          v.specs
        FROM catalog_product p
        LEFT JOIN v_catalog_product_specs_json v
          ON v.product_id = p.product_id;
        """
    )


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS v_catalog_product_with_specs;")
    op.execute("DROP VIEW IF EXISTS v_catalog_product_specs_json;")
