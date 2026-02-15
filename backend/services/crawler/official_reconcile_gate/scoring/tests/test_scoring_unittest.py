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
        self.assertIsNotNone(decision.retail_title)
        self.assertIsInstance(decision.matched_tokens, list)

    def test_deterministic_tie_break_selects_lexicographically_smaller_url(self) -> None:
        plan = {
            "plan_index": 1,
            "retail_url": "https://example.invalid/fan/1",
            "source": "coolpc",
            "category": "CASE_FAN",
            "brand_key": "corsair",
            "title": "CORSAIR LL120 RGB 120mm 三入組",
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
            matched_tokens=["focus"],
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
            matched_tokens=["focus"],
        )

        decision = select_best([candidate_b, candidate_a], plan=plan, topk=5, min_accept_score=3)
        self.assertEqual(decision.decision, "accepted")
        self.assertEqual(decision.chosen_official_url, "https://example.com/a-product")
        self.assertEqual(decision.retail_title, "CORSAIR LL120 RGB 120mm 三入組")
        self.assertIsNotNone(decision.retail_title)
        self.assertIsInstance(decision.matched_tokens, list)
        self.assertTrue(all("matched_tokens" in item for item in decision.top_k_summary))
        self.assertTrue(all(isinstance(item["matched_tokens"], list) for item in decision.top_k_summary))

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
        self.assertIsNotNone(decision.retail_title)
        self.assertIsInstance(decision.matched_tokens, list)

    def test_weak_match_only_is_downgraded_to_manual_review(self) -> None:
        plan = {
            "plan_index": 3,
            "retail_url": "https://example.invalid/mb/2",
            "source": "coolpc",
            "category": "MB",
            "brand_key": "asus",
        }
        weak_candidate = ScoreBreakdown(
            plan_index=3,
            retail_url=plan["retail_url"],
            source=plan["source"],
            category=plan["category"],
            brand_key=plan["brand_key"],
            official_url="https://www.asus.com/motherboards/rog-demo",
            total_score=5,
            components={"base": 5},
            reasons=["total=5"],
            matched_tokens=["rog"],
        )

        decision = select_best([weak_candidate], plan=plan, topk=5, min_accept_score=3)
        self.assertEqual(decision.decision, "needs_manual_review")
        self.assertTrue(decision.decision_reason.startswith("weak_match_only:"))

    def test_psu_category_mismatch_title_is_downgraded(self) -> None:
        plan = {
            "plan_index": 4,
            "retail_url": "https://example.invalid/psu/rog-thor-3",
            "source": "coolpc",
            "category": "PSU",
            "brand_key": "asus",
            "title": "ROG Thor III 1200W Hatsune Miku",
        }
        candidate = ScoreBreakdown(
            plan_index=4,
            retail_url=plan["retail_url"],
            source=plan["source"],
            category=plan["category"],
            brand_key=plan["brand_key"],
            official_url="https://example.com/fr/motherboards-components/gaming-cases/a23-miku/",
            total_score=5,
            components={"base": 5},
            reasons=["total=5"],
            matched_tokens=["hatsune", "miku"],
            page_title="Asus A23 Hatsune Miku Edition - Boîtiers PC gaming",
        )

        decision = select_best([candidate], plan=plan, topk=5, min_accept_score=3)
        self.assertEqual(decision.decision, "needs_manual_review")
        self.assertTrue(decision.decision_reason.startswith("category_mismatch:"))

    def test_psu_valid_title_can_still_be_accepted(self) -> None:
        plan = {
            "plan_index": 5,
            "retail_url": "https://example.invalid/psu/combat-dg-1000w",
            "source": "coolpc",
            "category": "PSU",
            "brand_key": "superflower",
            "title": "COMBAT DG 1000W ATX3.1 SUPER FLOWER",
        }
        candidate = ScoreBreakdown(
            plan_index=5,
            retail_url=plan["retail_url"],
            source=plan["source"],
            category=plan["category"],
            brand_key=plan["brand_key"],
            official_url="https://www.super-flower.com.tw/en/products/combat-dg-1000w",
            total_score=5,
            components={"base": 5},
            reasons=["total=5"],
            matched_tokens=["combat", "1000w"],
            page_title="COMBAT DG 1000W ATX3.1 SUPER FLOWER",
        )

        decision = select_best([candidate], plan=plan, topk=5, min_accept_score=3)
        self.assertEqual(decision.decision, "accepted")

    def test_psu_rog_articles_url_is_downgraded_to_manual_review(self) -> None:
        plan = {
            "plan_index": 6,
            "retail_url": "https://example.invalid/psu/loki",
            "source": "coolpc",
            "category": "PSU",
            "brand_key": "asus",
            "title": "ROG Loki SFX-L 1000W Platinum",
        }
        candidate = ScoreBreakdown(
            plan_index=6,
            retail_url=plan["retail_url"],
            source=plan["source"],
            category=plan["category"],
            brand_key=plan["brand_key"],
            official_url=(
                "https://rog.asus.com/articles/psus/"
                "power-your-high-octane-small-form-factor-pc-with-rogs-new-loki-psus/"
            ),
            total_score=5,
            components={"base": 5},
            reasons=["total=5"],
            matched_tokens=["hatsune", "miku"],
            page_title="ROG Loki 1000W Power Supply",
        )

        decision = select_best([candidate], plan=plan, topk=5, min_accept_score=3)
        self.assertEqual(decision.decision, "needs_manual_review")
        self.assertTrue(decision.decision_reason.startswith("non_product_page: expected-PSU url="))

    def test_psu_rog_power_supply_units_product_url_can_be_accepted(self) -> None:
        plan = {
            "plan_index": 7,
            "retail_url": "https://example.invalid/psu/thor",
            "source": "coolpc",
            "category": "PSU",
            "brand_key": "asus",
            "title": "ROG Thor 1200P3",
        }
        candidate = ScoreBreakdown(
            plan_index=7,
            retail_url=plan["retail_url"],
            source=plan["source"],
            category=plan["category"],
            brand_key=plan["brand_key"],
            official_url="https://rog.asus.com/us/power-supply-units/rog-thor/rog-thor-1200p3-gaming/",
            total_score=5,
            components={"base": 5},
            reasons=["total=5"],
            matched_tokens=["hatsune", "miku"],
            page_title="ROG Thor 1200P3 Gaming 1200W Power Supply",
        )

        decision = select_best([candidate], plan=plan, topk=5, min_accept_score=3)
        self.assertEqual(decision.decision, "accepted")


if __name__ == "__main__":
    unittest.main()
