# backend/services/crawler/official_reconcile_gate/extract.py
"""Generic signal extraction for T6 official reconciliation."""

from __future__ import annotations

import json
import re
from html import unescape
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin

from .types import OfficialSignals

_RE_WS = re.compile(r"\s+", flags=re.UNICODE)
_MAX_JSONLD_SCRIPTS = 10
_MAX_TEXT_HINT_CHARS = 300
_PRODUCT_TYPES = {"product", "productmodel"}
_IDENTIFIER_KEYS = ("mpn", "gtin", "gtin8", "gtin12", "gtin13", "gtin14")


class _LightHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.canonical_href: str | None = None
        self.og_title: str | None = None
        self.page_title: str | None = None
        self.jsonld_scripts: list[str] = []

        self._in_title = False
        self._title_chunks: list[str] = []
        self._capture_jsonld = False
        self._jsonld_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        attrs_map = _attrs_to_map(attrs)

        if tag_name == "link" and self.canonical_href is None:
            rel = attrs_map.get("rel", "")
            href = attrs_map.get("href")
            if href and _has_canonical_rel(rel):
                self.canonical_href = href.strip() or None

        if tag_name == "meta" and self.og_title is None:
            prop = attrs_map.get("property", "").strip().lower()
            if prop == "og:title":
                content = attrs_map.get("content", "").strip()
                if content:
                    self.og_title = _clean_text(content)

        if tag_name == "title" and self.page_title is None:
            self._in_title = True
            self._title_chunks = []

        if (
            tag_name == "script"
            and len(self.jsonld_scripts) < _MAX_JSONLD_SCRIPTS
            and _is_jsonld_type(attrs_map.get("type", ""))
        ):
            self._capture_jsonld = True
            self._jsonld_chunks = []
        else:
            self._capture_jsonld = False

    def handle_endtag(self, tag: str) -> None:
        tag_name = tag.lower()

        if tag_name == "title" and self._in_title:
            title = _clean_text("".join(self._title_chunks))
            if title and self.page_title is None:
                self.page_title = title
            self._in_title = False
            self._title_chunks = []

        if tag_name == "script" and self._capture_jsonld:
            payload = "".join(self._jsonld_chunks).strip()
            if payload and len(self.jsonld_scripts) < _MAX_JSONLD_SCRIPTS:
                self.jsonld_scripts.append(payload)
            self._capture_jsonld = False
            self._jsonld_chunks = []

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_chunks.append(data)
        if self._capture_jsonld and len(self.jsonld_scripts) < _MAX_JSONLD_SCRIPTS:
            self._jsonld_chunks.append(data)


def extract_signals(*, official_url: str, http_status: int, html_text: str) -> OfficialSignals:
    parser = _LightHTMLParser()
    parser.feed(html_text)
    parser.close()

    canonical_url: str | None = None
    if parser.canonical_href:
        canonical_url = urljoin(official_url, parser.canonical_href).strip() or None

    product_title = parser.og_title or parser.page_title
    jsonld_title, model, identifiers = _extract_from_jsonld(parser.jsonld_scripts)

    if product_title is None:
        product_title = jsonld_title

    text_hint = _build_text_hint(html_text)

    return {
        "official_url": official_url,
        "http_status": http_status,
        "canonical_url": canonical_url,
        "product_title": product_title,
        "model": model,
        "identifiers": identifiers,
        "specs": {},
        "text_hint": text_hint,
    }


def _attrs_to_map(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
    mapped: dict[str, str] = {}
    for key, value in attrs:
        if not key:
            continue
        mapped[key.lower()] = value or ""
    return mapped


def _has_canonical_rel(rel_value: str) -> bool:
    rel_tokens = rel_value.strip().lower().split()
    return "canonical" in rel_tokens


def _is_jsonld_type(type_value: str) -> bool:
    return type_value.strip().lower().startswith("application/ld+json")


def _clean_text(text: str) -> str:
    return _RE_WS.sub(" ", unescape(text)).strip()


def _build_text_hint(html_text: str) -> str | None:
    cleaned = _clean_text(html_text.replace("\r", " ").replace("\n", " "))
    if not cleaned:
        return None
    return cleaned[:_MAX_TEXT_HINT_CHARS]


def _extract_from_jsonld(
    jsonld_scripts: list[str],
) -> tuple[str | None, str | None, dict[str, str] | None]:
    product_title: str | None = None
    model: str | None = None
    identifiers: dict[str, str] = {}

    for payload in jsonld_scripts:
        parsed = _safe_json_load(payload)
        if parsed is None:
            continue

        for node in _iter_product_nodes(parsed):
            if product_title is None:
                product_title = _as_non_empty_str(node.get("name"))
            if model is None:
                model = _as_non_empty_str(node.get("model"))

            for key in _IDENTIFIER_KEYS:
                if key in identifiers:
                    continue
                val = _as_non_empty_str(node.get(key))
                if val is not None:
                    identifiers[key] = val

    return product_title, model, (identifiers or None)


def _safe_json_load(payload: str) -> Any | None:
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return None


def _iter_product_nodes(value: Any) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    _collect_product_nodes(value, nodes)
    return nodes


def _collect_product_nodes(value: Any, out: list[dict[str, Any]]) -> None:
    if isinstance(value, dict):
        if _is_product_type(value.get("@type")):
            out.append(value)
        for child in value.values():
            _collect_product_nodes(child, out)
        return

    if isinstance(value, list):
        for item in value:
            _collect_product_nodes(item, out)


def _is_product_type(value: Any) -> bool:
    if isinstance(value, str):
        return _normalize_type_token(value) in _PRODUCT_TYPES

    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and _normalize_type_token(item) in _PRODUCT_TYPES:
                return True
    return False


def _normalize_type_token(type_name: str) -> str:
    token = type_name.strip().lower()
    if "/" in token:
        token = token.rsplit("/", 1)[-1]
    if "#" in token:
        token = token.rsplit("#", 1)[-1]
    return token


def _as_non_empty_str(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = _clean_text(value)
    if not cleaned:
        return None
    return cleaned
