from __future__ import annotations

from urllib.parse import urlsplit


def is_asus_psu_product_url(url: str) -> bool:
    parts = urlsplit(url)
    host = (parts.netloc or "").strip().lower()
    path = (parts.path or "/").lower()

    if host in {"rog.asus.com", "www.rog.asus.com"}:
        return "/power-supply-units/" in path
    if host in {"asus.com", "www.asus.com"}:
        return "/power-supply-units/" in path or "/motherboards-components/power-supply-units/" in path
    return False


def is_candidate_allowed_for_plan(category: str, brand_key: str | None, url: str) -> bool:
    if category.strip().upper() != "PSU":
        return True
    if (brand_key or "").strip().lower() != "asus":
        return True
    return is_asus_psu_product_url(url)
