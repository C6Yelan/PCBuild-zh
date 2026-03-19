# backend/tests/chat/context_pack/test_retrieval_ordering.py
from sqlalchemy.dialects import postgresql

from backend.services.chat.context_pack.retrieval import (
    P1Demand,
    build_category_retrieval_stmt,
    describe_order_by,
)


def _normalize_sql(sql: str) -> str:
    return " ".join(sql.split())


def test_p1_query_has_deterministic_order_by() -> None:
    demand = P1Demand(min_price=1000, max_price=5000)

    stmt1 = build_category_retrieval_stmt(
        category="CPU",
        top_k=3,
        demand=demand,
    )
    stmt2 = build_category_retrieval_stmt(
        category="CPU",
        top_k=3,
        demand=demand,
    )

    sql1 = _normalize_sql(
        str(
            stmt1.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )
    )
    sql2 = _normalize_sql(
        str(
            stmt2.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )
    )

    assert sql1 == sql2
    assert "catalog_price_snapshot.price >= 1000" in sql1
    assert "catalog_price_snapshot.price <= 5000" in sql1
    assert "ORDER BY CASE WHEN (catalog_price_snapshot.price IS NOT NULL AND catalog_price_snapshot.price >= 1000 AND catalog_price_snapshot.price <= 5000) THEN 0 WHEN (catalog_price_snapshot.price IS NOT NULL) THEN 1 ELSE 2 END ASC" in sql1
    assert "abs(catalog_price_snapshot.price - 3000)" in sql1
    assert "catalog_price_snapshot.price ASC NULLS LAST, catalog_product.product_id ASC" in sql1
    assert "LIMIT 3" in sql1
    assert "catalog_price_snapshot.run_id = catalog_product.last_seen_run_id" in sql1
    assert "catalog_product.last_seen_run_id = '11111111-1111-1111-1111-111111111111'" not in sql1


def test_p1_query_keeps_existing_order_when_no_budget_fields() -> None:
    stmt = build_category_retrieval_stmt(
        category="CPU",
        top_k=5,
        demand=None,
    )

    sql = _normalize_sql(
        str(
            stmt.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )
    )

    assert "ORDER BY catalog_price_snapshot.price ASC NULLS LAST, catalog_product.product_id ASC" in sql
    assert describe_order_by(None) == "price ASC NULLS LAST, part_id ASC"


def test_p1_query_uses_target_price_when_provided() -> None:
    stmt = build_category_retrieval_stmt(
        category="GPU",
        top_k=5,
        demand=P1Demand(target_price=18000),
    )

    sql = _normalize_sql(
        str(
            stmt.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )
    )

    assert "abs(catalog_price_snapshot.price - 18000)" in sql
