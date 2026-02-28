# backend/tools/db/p1_retrieve_candidates.py
from __future__ import annotations

import json

from backend.db import SessionLocal
from backend.services.catalog.p1_retrieval import retrieve_topk_candidates
from backend.services.chat.contracts import P1Demand

SAMPLE_CATEGORIES = ["cpu", "mb", "gpu", "ram"]
SAMPLE_TOP_K = 5
SAMPLE_DEMAND = P1Demand(budget=30000, keyword=None)
SAMPLE_ENV = "prod"


def main() -> int:
    with SessionLocal() as db:
        result = retrieve_topk_candidates(
            db,
            categories=SAMPLE_CATEGORIES,
            top_k=SAMPLE_TOP_K,
            demand=SAMPLE_DEMAND,
            env=SAMPLE_ENV,
        )

    print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
