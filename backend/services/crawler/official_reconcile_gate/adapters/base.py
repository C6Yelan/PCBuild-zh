# backend/services/crawler/official_reconcile_gate/adapters/base.py
from __future__ import annotations

from typing import Protocol

from ..fetch import OfficialFetcher
from ..types import OfficialDocument


class OfficialAdapter(Protocol):
    def fetch_document(self, official_url: str, *, fetcher: OfficialFetcher) -> OfficialDocument:
        ...
