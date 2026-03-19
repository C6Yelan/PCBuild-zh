# backend/services/chat/context_pack/retrieval.py
"""Chat retrieval implementation.

``retrieve_topk_candidates`` is the callable boundary used by chat orchestration.
``build_category_retrieval_stmt`` is a stable SQL seam for ordering-contract
tests and future refactors without reaching into private helpers.
"""

from __future__ import annotations

from .retrieval_contracts import CandidatePart, P1Demand, P1RetrievalResult
from .retrieval_runtime import retrieve_topk_candidates
from .retrieval_sql import P1_ORDER_BY, build_category_retrieval_stmt, describe_order_by

__all__ = [
    "CandidatePart",
    "P1Demand",
    "P1RetrievalResult",
    "P1_ORDER_BY",
    "build_category_retrieval_stmt",
    "describe_order_by",
    "retrieve_topk_candidates",
]
