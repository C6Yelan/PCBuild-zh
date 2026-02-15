from __future__ import annotations

import unittest
from pathlib import Path

from backend.services.crawler.official_reconcile_gate.planning.registry import load_official_registry


class TestRegistryPSUBackfill(unittest.TestCase):
    def test_psu_brands_have_allowed_domains(self) -> None:
        registry_path = Path(__file__).resolve().parents[1] / "data" / "official_registry.v1.json"
        registry = load_official_registry(registry_path)

        expected_hosts_by_brand = {
            "coolermaster": "www.coolermaster.com",
            "cougar": "cougargaming.com",
            "fsp": "www.fsp-group.com",
            "msi": "www.msi.com",
            "silverstone": "www.silverstonetek.com",
            "superflower": "www.super-flower.com.tw",
        }

        entries = {entry.brand_key: entry for entry in registry.brands}
        for brand_key, expected_host in expected_hosts_by_brand.items():
            self.assertIn(brand_key, entries, msg=f"missing brand_key={brand_key}")
            allowed_domains = entries[brand_key].allowed_domains
            self.assertIsInstance(allowed_domains, list, msg=f"{brand_key} allowed_domains must be list")
            self.assertIn(expected_host, allowed_domains, msg=f"{brand_key} missing host={expected_host}")
            self.assertGreater(len(allowed_domains), 0, msg=f"{brand_key} allowed_domains must not be empty")

    def test_asus_psu_entrypoints_and_allowed_domains(self) -> None:
        registry_path = Path(__file__).resolve().parents[1] / "data" / "official_registry.v1.json"
        registry = load_official_registry(registry_path)
        entries = {entry.brand_key: entry for entry in registry.brands}

        self.assertIn("asus", entries, msg="missing brand_key=asus")
        asus = entries["asus"]

        self.assertIn("www.asus.com", asus.allowed_domains)
        self.assertIn("rog.asus.com", asus.allowed_domains)

        expected_entrypoints = {
            "https://rog.asus.com/sitemap.xml",
            "https://www.asus.com/sitemap.xml",
        }
        self.assertTrue(
            expected_entrypoints.issubset(set(asus.sitemap_urls)),
            msg="asus sitemap_urls missing expected sitemap xml entrypoints",
        )


if __name__ == "__main__":
    unittest.main()
