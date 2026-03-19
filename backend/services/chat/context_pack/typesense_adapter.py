from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import httpx
import sqlalchemy as sa
from sqlalchemy.orm import Session

from backend.models.catalog import (
    CatalogBrand,
    CatalogPriceSnapshot,
    CatalogProduct,
    CatalogProductSpec,
    CatalogSource,
    CatalogSpecKey,
)
from backend.models.crawler_publication import CrawlerPublicationPointer

from .retrieval_contracts import CandidatePart, P1Demand
from .retrieval_sql import build_specs_subquery

DEFAULT_TYPESENSE_QUERY_BY = ("searchable_text", "title", "model", "brand", "sku")
DEFAULT_TYPESENSE_QUERY_BY_WEIGHTS = (6, 5, 4, 3, 2)
SEARCHABLE_SPEC_KEYS = (
    "brand_hint",
    "maker_hint",
    "model_hint",
    "socket",
    "socket_hint",
    "chipset",
    "chipset_hint",
    "gpu_chip_hint",
    "memory_type_hint",
    "ddr_gen_hint",
    "capacity_gb_hint",
    "capacity_gib",
    "vram_gb",
    "vram_gb_hint",
    "form_factor",
    "form_factor_hint",
    "wattage_w_hint",
    "power_w_hint",
    "pcie_gen_hint",
    "interface_hint",
)


class TypesenseError(RuntimeError):
    """Base runtime error for Typesense integration."""


class TypesenseConfigurationError(TypesenseError):
    """Raised when Typesense is enabled but required runtime config is missing."""


class TypesenseRequestError(TypesenseError):
    """Raised when Typesense returns a non-success response."""


@dataclass(frozen=True, slots=True)
class TypesenseCategorySearchResult:
    found: int
    candidates: list[CandidatePart]


def _normalize_query_text(query_text: str | None) -> str:
    if query_text is None:
        return "*"
    normalized = query_text.strip()
    return normalized or "*"


def _budget_target_price(demand: P1Demand | None) -> int | None:
    if demand is None:
        return None
    if demand.target_price is not None:
        return demand.target_price
    if demand.min_price is not None and demand.max_price is not None:
        return (demand.min_price + demand.max_price) // 2
    if demand.max_price is not None:
        return demand.max_price
    if demand.min_price is not None:
        return demand.min_price
    return None


def build_typesense_filter_by(
    *,
    env: str,
    category: str,
    demand: P1Demand | None,
) -> str:
    filters = [
        f"env:={json.dumps(env, ensure_ascii=True)}",
        f"category:={json.dumps(category, ensure_ascii=True)}",
        "available:=true",
    ]
    if demand is not None:
        if demand.min_price is not None:
            filters.append(f"price_twd:>={int(demand.min_price)}")
        if demand.max_price is not None:
            filters.append(f"price_twd:<={int(demand.max_price)}")
    return " && ".join(filters)


def build_typesense_sort_by(demand: P1Demand | None, *, has_query_text: bool) -> str:
    order_parts: list[str] = []
    if has_query_text:
        order_parts.append("_text_match:desc")

    target_price = _budget_target_price(demand)
    if target_price is not None:
        # Typesense minimal integration: no custom abs(target-price) expression here.
        # Keep budget filters in filter_by and use deterministic price ordering.
        order_parts.append("price_twd:asc")
    else:
        order_parts.append("price_twd:asc")

    order_parts.append("part_id:asc")
    return ",".join(order_parts)


def build_typesense_search_params(
    *,
    env: str,
    category: str,
    top_k: int,
    demand: P1Demand | None,
) -> dict[str, str]:
    normalized_query = _normalize_query_text(demand.query_text if demand is not None else None)
    has_query_text = normalized_query != "*"
    return {
        "q": normalized_query,
        "query_by": ",".join(DEFAULT_TYPESENSE_QUERY_BY),
        "query_by_weights": ",".join(str(weight) for weight in DEFAULT_TYPESENSE_QUERY_BY_WEIGHTS),
        "filter_by": build_typesense_filter_by(env=env, category=category, demand=demand),
        "sort_by": build_typesense_sort_by(demand, has_query_text=has_query_text),
        "per_page": str(max(1, min(int(top_k), 200))),
    }


def build_parts_collection_schema(collection_name: str) -> dict[str, Any]:
    return {
        "name": collection_name,
        "fields": [
            {"name": "part_id", "type": "string", "sort": True},
            {"name": "env", "type": "string", "facet": True},
            {"name": "category", "type": "string", "facet": True},
            {"name": "brand", "type": "string", "optional": True},
            {"name": "title", "type": "string"},
            {"name": "model", "type": "string", "optional": True},
            {"name": "sku", "type": "string", "optional": True},
            {"name": "searchable_text", "type": "string"},
            {"name": "price_twd", "type": "int32", "optional": True, "sort": True},
            {"name": "source", "type": "string", "optional": True, "facet": True},
            {"name": "source_url", "type": "string", "optional": True},
            {"name": "available", "type": "bool"},
            {"name": "spec_summary", "type": "string", "optional": True},
        ],
        "default_sorting_field": "price_twd",
    }


def _resolve_typesense_components(settings: Any) -> tuple[str, str, float, str]:
    host = str(getattr(settings, "typesense_host", "")).strip()
    protocol = str(getattr(settings, "typesense_protocol", "http")).strip().lower()
    collection_name = str(getattr(settings, "typesense_collection_parts", "")).strip()
    timeout_seconds = float(getattr(settings, "typesense_timeout_seconds", 2.0))

    api_key_getter = getattr(settings, "get_typesense_api_key", None)
    api_key = api_key_getter() if callable(api_key_getter) else getattr(settings, "typesense_api_key", None)
    if hasattr(api_key, "get_secret_value"):
        api_key = api_key.get_secret_value()
    if isinstance(api_key, bytes):
        api_key = api_key.decode("utf-8", errors="ignore")
    if not host or not collection_name or timeout_seconds <= 0 or not api_key:
        raise TypesenseConfigurationError(
            "Typesense is enabled but TYPESENSE_HOST / TYPESENSE_API_KEY / "
            "TYPESENSE_COLLECTION_PARTS / TYPESENSE_TIMEOUT_SECONDS are not fully configured"
        )
    port = int(getattr(settings, "typesense_port", 8108))
    if protocol not in {"http", "https"}:
        raise TypesenseConfigurationError("TYPESENSE_PROTOCOL must be http or https")
    base_url = f"{protocol}://{host}:{port}"
    return base_url, str(api_key), timeout_seconds, collection_name


class TypesenseClient:
    def __init__(self, settings: Any, *, client: httpx.Client | None = None) -> None:
        base_url, api_key, timeout_seconds, collection_name = _resolve_typesense_components(settings)
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self.collection_name = collection_name
        self._client = client

    def _headers(self) -> dict[str, str]:
        return {
            "X-TYPESENSE-API-KEY": self._api_key,
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        json_body: Any = None,
        content: str | bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        request_headers = dict(self._headers())
        if headers:
            request_headers.update(headers)

        if self._client is not None:
            response = self._client.request(
                method,
                f"{self._base_url}{path}",
                params=params,
                json=json_body,
                content=content,
                headers=request_headers,
                timeout=self._timeout_seconds,
            )
        else:
            with httpx.Client(timeout=self._timeout_seconds) as client:
                response = client.request(
                    method,
                    f"{self._base_url}{path}",
                    params=params,
                    json=json_body,
                    content=content,
                    headers=request_headers,
                )

        if response.status_code >= 400:
            raise TypesenseRequestError(
                f"Typesense {method} {path} failed with status {response.status_code}"
            )
        return response

    def collection_exists(self) -> bool:
        try:
            self._request("GET", f"/collections/{self.collection_name}")
            return True
        except TypesenseRequestError as exc:
            if "status 404" in str(exc):
                return False
            raise

    def create_collection(self, *, force: bool = False) -> None:
        if force:
            self.delete_collection(ignore_missing=True)
        if self.collection_exists():
            return
        self._request(
            "POST",
            "/collections",
            json_body=build_parts_collection_schema(self.collection_name),
        )

    def delete_collection(self, *, ignore_missing: bool = False) -> None:
        try:
            self._request("DELETE", f"/collections/{self.collection_name}")
        except TypesenseRequestError as exc:
            if ignore_missing and "status 404" in str(exc):
                return
            raise

    def search(self, params: Mapping[str, str]) -> dict[str, Any]:
        response = self._request(
            "GET",
            f"/collections/{self.collection_name}/documents/search",
            params=params,
        )
        return response.json()

    def import_documents(self, documents: Sequence[dict[str, Any]]) -> dict[str, int]:
        if not documents:
            return {"success": 0, "failed": 0}
        payload = "\n".join(json.dumps(document, ensure_ascii=False) for document in documents)
        response = self._request(
            "POST",
            f"/collections/{self.collection_name}/documents/import",
            params={"action": "upsert"},
            content=payload.encode("utf-8"),
            headers={"Content-Type": "text/plain"},
        )
        success = 0
        failed = 0
        for raw_line in response.text.splitlines():
            if not raw_line.strip():
                continue
            line = json.loads(raw_line)
            if line.get("success") is True:
                success += 1
            else:
                failed += 1
        return {"success": success, "failed": failed}


def _coerce_spec_value(value: Any) -> str:
    return " ".join(str(value).strip().split())


def _build_spec_summary(key_specs: Mapping[str, Any]) -> str:
    parts: list[str] = []
    for key in SEARCHABLE_SPEC_KEYS:
        raw_value = key_specs.get(key)
        if raw_value is None:
            continue
        normalized_value = _coerce_spec_value(raw_value)
        if normalized_value:
            parts.append(f"{key} {normalized_value}")
    return " ".join(parts)


def _build_searchable_text(
    *,
    brand: str | None,
    title: str,
    model: str | None,
    sku: str | None,
    spec_summary: str,
) -> str:
    parts = [brand or "", title, model or "", sku or "", spec_summary]
    return " ".join(part for part in parts if part).strip()


def _index_specs_subquery() -> sa.Subquery:
    return (
        sa.select(
            CatalogProductSpec.product_id.label("product_id"),
            sa.func.jsonb_object_agg(CatalogSpecKey.key, CatalogProductSpec.value_text).label("key_specs"),
        )
        .select_from(CatalogProductSpec)
        .join(CatalogSpecKey, CatalogSpecKey.id == CatalogProductSpec.spec_key_id)
        .group_by(CatalogProductSpec.product_id)
        .subquery()
    )


def build_parts_index_batch_stmt(
    *,
    env: str,
    limit: int,
    offset: int,
) -> sa.Select[Any]:
    ptr_sq = (
        sa.select(CrawlerPublicationPointer.run_id)
        .where(CrawlerPublicationPointer.env == env)
        .scalar_subquery()
    )
    specs_sq = _index_specs_subquery()
    return (
        sa.select(
            CatalogProduct.product_id.label("part_id"),
            CatalogProduct.category,
            CatalogBrand.name.label("brand"),
            CatalogProduct.title.label("title"),
            CatalogProduct.sku_hint.label("sku"),
            CatalogSource.code.label("source"),
            CatalogProduct.url.label("source_url"),
            CatalogPriceSnapshot.price.label("price_twd"),
            specs_sq.c.key_specs.label("key_specs"),
        )
        .select_from(CatalogProduct)
        .join(CatalogSource, CatalogSource.id == CatalogProduct.source_id)
        .join(CatalogBrand, CatalogBrand.id == CatalogProduct.brand_id, isouter=True)
        .join(
            CatalogPriceSnapshot,
            sa.and_(
                CatalogPriceSnapshot.product_id == CatalogProduct.product_id,
                CatalogPriceSnapshot.run_id == ptr_sq,
            ),
            isouter=True,
        )
        .join(specs_sq, specs_sq.c.product_id == CatalogProduct.product_id, isouter=True)
        .where(CatalogProduct.last_seen_run_id == ptr_sq)
        .order_by(CatalogProduct.product_id.asc())
        .limit(limit)
        .offset(offset)
    )


def build_typesense_document(row: Mapping[str, Any], *, env: str) -> dict[str, Any]:
    key_specs = row["key_specs"] if isinstance(row.get("key_specs"), dict) else {}
    model = _coerce_spec_value(key_specs.get("model_hint", "")) or (row.get("sku") or "")
    spec_summary = _build_spec_summary(key_specs)
    part_id = str(row["part_id"])
    return {
        "id": f"{env}:{part_id}",
        "part_id": part_id,
        "env": env,
        "category": str(row["category"]),
        "brand": _coerce_spec_value(row.get("brand", "")),
        "title": _coerce_spec_value(row.get("title", "")),
        "model": model,
        "sku": _coerce_spec_value(row.get("sku", "")),
        "searchable_text": _build_searchable_text(
            brand=row.get("brand"),
            title=str(row.get("title", "")),
            model=model,
            sku=row.get("sku"),
            spec_summary=spec_summary,
        ),
        "price_twd": row.get("price_twd"),
        "source": _coerce_spec_value(row.get("source", "")),
        "source_url": _coerce_spec_value(row.get("source_url", "")),
        "available": True,
        "spec_summary": spec_summary,
    }


def hydrate_candidates_by_part_ids(
    db: Session,
    *,
    part_ids: Sequence[str],
) -> list[CandidatePart]:
    normalized_part_ids = [part_id for part_id in part_ids if part_id]
    if not normalized_part_ids:
        return []

    specs_sq = build_specs_subquery()
    rows = list(
        db.execute(
            sa.select(
                CatalogProduct.product_id.label("part_id"),
                CatalogProduct.category,
                CatalogProduct.title.label("display_name"),
                specs_sq.c.key_specs.label("key_specs"),
                CatalogPriceSnapshot.price.label("price"),
                CatalogSource.code.label("source"),
                CatalogProduct.url.label("source_url"),
                CatalogProduct.last_seen_run_id.label("item_run_id"),
            )
            .select_from(CatalogProduct)
            .join(CatalogSource, CatalogSource.id == CatalogProduct.source_id)
            .join(
                CatalogPriceSnapshot,
                sa.and_(
                    CatalogPriceSnapshot.product_id == CatalogProduct.product_id,
                    CatalogPriceSnapshot.run_id == CatalogProduct.last_seen_run_id,
                ),
                isouter=True,
            )
            .join(specs_sq, specs_sq.c.product_id == CatalogProduct.product_id, isouter=True)
            .where(
                CatalogProduct.product_id.in_(normalized_part_ids),
                CatalogProduct.last_seen_run_id.is_not(None),
            )
        ).mappings()
    )
    by_part_id = {
        str(row["part_id"]): CandidatePart(
            part_id=str(row["part_id"]),
            category=str(row["category"]),
            display_name=str(row["display_name"]),
            key_specs=row["key_specs"] if isinstance(row["key_specs"], dict) else {},
            price=row["price"],
            source=str(row["source"]),
            source_url=str(row["source_url"]),
            run_id=str(row["item_run_id"]),
        )
        for row in rows
    }
    return [by_part_id[part_id] for part_id in normalized_part_ids if part_id in by_part_id]


def search_parts(
    db: Session,
    *,
    settings: Any,
    categories: Sequence[str],
    top_k: int,
    demand: P1Demand | None,
    env: str,
    client: TypesenseClient | None = None,
) -> dict[str, TypesenseCategorySearchResult]:
    ts_client = client or TypesenseClient(settings)
    results: dict[str, TypesenseCategorySearchResult] = {}

    for category in categories:
        params = build_typesense_search_params(
            env=env,
            category=category,
            top_k=top_k,
            demand=demand,
        )
        payload = ts_client.search(params)
        hits = payload.get("hits")
        part_ids: list[str] = []
        if isinstance(hits, list):
            for hit in hits:
                if not isinstance(hit, Mapping):
                    continue
                document = hit.get("document")
                if not isinstance(document, Mapping):
                    continue
                part_id = document.get("part_id")
                if part_id is None:
                    continue
                part_ids.append(str(part_id))
        results[str(category)] = TypesenseCategorySearchResult(
            found=int(payload.get("found") or 0),
            candidates=hydrate_candidates_by_part_ids(db, part_ids=part_ids),
        )

    return results
