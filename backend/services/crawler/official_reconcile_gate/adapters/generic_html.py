# backend/services/crawler/official_reconcile_gate/adapters/generic_html.py
from __future__ import annotations

from ..extract import ExtractError, extract_official_document
from ..fetch import OfficialFetcher
from ..types import OfficialDocument


class GenericHtmlOfficialAdapter:
    def fetch_document(self, official_url: str, *, fetcher: OfficialFetcher) -> OfficialDocument:
        response = fetcher.fetch(official_url)
        try:
            return extract_official_document(response)
        except ExtractError:
            raise
        except Exception as e:  # pragma: no cover - defensive wrapper
            raise ExtractError(str(e)) from e
