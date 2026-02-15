from __future__ import annotations

import unittest

from backend.services.crawler.official_reconcile_gate.discovery.candidate_filters import (
    is_candidate_allowed_for_plan,
)


class TestCandidateFilters(unittest.TestCase):
    def test_asus_psu_blocks_rog_articles_url(self) -> None:
        allowed = is_candidate_allowed_for_plan(
            "PSU",
            "asus",
            "https://rog.asus.com/ch-fr/articles/psus/power-your-high-octane-small-form-factor-pc-with-rogs-new-loki-psus/",
        )
        self.assertFalse(allowed)

    def test_asus_psu_allows_rog_power_supply_units_url(self) -> None:
        allowed = is_candidate_allowed_for_plan(
            "PSU",
            "asus",
            "https://rog.asus.com/es/power-supply-units/rog-loki/rog-loki-1000p-sfx-l-gaming-model/wtb/",
        )
        self.assertTrue(allowed)

    def test_non_psu_does_not_filter_rog_articles(self) -> None:
        allowed = is_candidate_allowed_for_plan(
            "GPU",
            "asus",
            "https://rog.asus.com/ch-fr/articles/psus/power-your-high-octane-small-form-factor-pc-with-rogs-new-loki-psus/",
        )
        self.assertTrue(allowed)

    def test_non_asus_brand_does_not_filter_rog_articles(self) -> None:
        allowed = is_candidate_allowed_for_plan(
            "PSU",
            "msi",
            "https://rog.asus.com/ch-fr/articles/psus/power-your-high-octane-small-form-factor-pc-with-rogs-new-loki-psus/",
        )
        self.assertTrue(allowed)

    def test_asus_psu_blocks_asus_non_psu_page(self) -> None:
        allowed = is_candidate_allowed_for_plan(
            "PSU",
            "asus",
            "https://www.asus.com/motherboards-components/cases/",
        )
        self.assertFalse(allowed)


if __name__ == "__main__":
    unittest.main()
