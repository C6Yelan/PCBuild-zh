from __future__ import annotations

import unittest

from backend.services.crawler.official_reconcile_gate.scoring.scorer import score_candidate
from backend.services.crawler.official_reconcile_gate.scoring.selector import select_best
from backend.services.crawler.official_reconcile_gate.scoring.types import ScoreBreakdown


class TestScoringPhaseE(unittest.TestCase):
    def test_block_reason_lowers_score_and_can_trigger_manual_review(self) -> None:
        plan = {
            "plan_index": 0,
            "retail_url": "https://example.invalid/psu/1",
            "source": "coolpc",
            "category": "PSU",
            "brand_key": "seasonic",
            "query_terms": ["FOCUS GX-750"],
        }
        candidate = {
            "official_url": "https://seasonic.com/focus-gx-750",
            "score": 3,
            "evidence": {"matched_tokens": ["focus"]},
        }
        snippet = (
            "<html><head><title>Official Product Detail</title></head>"
            "<body>Product detail and specification content with stable long text for scoring.</body></html>"
        )
        clean_evidence = {
            "body_snippet": snippet,
            "content_type": "text/html",
            "block_reason": None,
        }
        blocked_evidence = {
            "body_snippet": snippet,
            "content_type": "text/html",
            "block_reason": "waf_or_captcha",
        }

        clean_score = score_candidate(plan, candidate, clean_evidence)
        blocked_score = score_candidate(plan, candidate, blocked_evidence)

        self.assertGreater(clean_score.total_score, blocked_score.total_score)
        decision = select_best([blocked_score], plan=plan, topk=5, min_accept_score=3)
        self.assertEqual(decision.decision, "needs_manual_review")

    def test_deterministic_tie_break_selects_lexicographically_smaller_url(self) -> None:
        plan = {
            "plan_index": 1,
            "retail_url": "https://example.invalid/fan/1",
            "source": "coolpc",
            "category": "CASE_FAN",
            "brand_key": "corsair",
        }
        candidate_a = ScoreBreakdown(
            plan_index=1,
            retail_url=plan["retail_url"],
            source=plan["source"],
            category=plan["category"],
            brand_key=plan["brand_key"],
            official_url="https://example.com/a-product",
            total_score=5,
            components={"base": 5},
            reasons=["total=5"],
        )
        candidate_b = ScoreBreakdown(
            plan_index=1,
            retail_url=plan["retail_url"],
            source=plan["source"],
            category=plan["category"],
            brand_key=plan["brand_key"],
            official_url="https://example.com/b-product",
            total_score=5,
            components={"base": 5},
            reasons=["total=5"],
        )

        decision = select_best([candidate_b, candidate_a], plan=plan, topk=5, min_accept_score=3)
        self.assertEqual(decision.decision, "accepted")
        self.assertEqual(decision.chosen_official_url, "https://example.com/a-product")

    def test_no_candidates_returns_no_candidates_decision(self) -> None:
        plan = {
            "plan_index": 2,
            "retail_url": "https://example.invalid/mb/1",
            "source": "coolpc",
            "category": "MB",
            "brand_key": "asus",
        }
        decision = select_best([], plan=plan, topk=5, min_accept_score=3)
        self.assertEqual(decision.decision, "no_candidates")
        self.assertIsNone(decision.chosen_official_url)
        self.assertEqual(decision.confidence, 0)


if __name__ == "__main__":
    unittest.main()
