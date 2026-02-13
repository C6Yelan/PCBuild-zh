# backend/services/crawler/official_reconcile_gate/adapters/__init__.py
from .base import OfficialAdapter
from .generic_html import GenericHtmlOfficialAdapter

__all__ = ["OfficialAdapter", "GenericHtmlOfficialAdapter"]
