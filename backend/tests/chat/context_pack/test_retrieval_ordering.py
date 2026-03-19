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
    demand = P1Demand(
        query_text="RTX 5070 gaming",
        min_price=1000,
        max_price=5000,
    )

    stmt1 = build_category_retrieval_stmt(
        category="CPU",
        top_k=3,
        demand=demand,
        use_trigram=True,
    )
    stmt2 = build_category_retrieval_stmt(
        category="CPU",
        top_k=3,
        demand=demand,
        use_trigram=True,
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
    assert "websearch_to_tsquery('simple', 'RTX 5070 gaming')" in sql1
    assert "to_tsvector('simple'" in sql1
    assert "ts_rank_cd(" in sql1
    assert "similarity(" in sql1
    assert "catalog_price_snapshot.price >= 1000" in sql1
    assert "catalog_price_snapshot.price <= 5000" in sql1
    assert "ORDER BY CASE WHEN (to_tsvector('simple'" in sql1
    assert "THEN 0 WHEN (greatest(similarity" in sql1
    assert "abs(catalog_price_snapshot.price - 3000)" in sql1
    assert "catalog_product.product_id ASC" in sql1
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


def test_p1_query_uses_fts_without_trigram_when_disabled() -> None:
    stmt = build_category_retrieval_stmt(
        category="GPU",
        top_k=5,
        demand=P1Demand(query_text="Ryzen 9700X"),
        use_trigram=False,
    )

    sql = _normalize_sql(
        str(
            stmt.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )
    )

    assert "websearch_to_tsquery('simple', 'Ryzen 9700X')" in sql
    assert "ts_rank_cd(" in sql
    assert "similarity(" not in sql
    assert describe_order_by(P1Demand(query_text="Ryzen 9700X"), use_trigram=False) == "search_match, fts_rank DESC, part_id ASC"
