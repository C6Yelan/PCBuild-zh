# backend/services/chat/contracts/types.py
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


SpecValue = str | int | float | bool | None
ChatRole = Literal["system", "user", "assistant", "ai"]
NormalizedRequestMode = Literal["single_part", "build", "upgrade", "unknown"]
NormalizedUsageProfile = Literal[
    "gaming",
    "office",
    "creator",
    "workstation",
    "mixed",
    "unknown",
]
NormalizedSizePreference = Literal["ITX", "mATX", "ATX", "unknown"]
NormalizedExplanationStyle = Literal["brief", "normal", "detailed"]
NormalizationSource = Literal["ai_structured", "ai_repaired_json", "rule_fallback"]
_ALLOWED_CATEGORIES = ("CPU", "GPU", "MB", "RAM", "SSD", "PSU", "CASE")
_CATEGORY_ALIASES = {
    "CPU": "CPU",
    "PROCESSOR": "CPU",
    "處理器": "CPU",
    "GPU": "GPU",
    "顯卡": "GPU",
    "DISPLAYCARD": "GPU",
    "MB": "MB",
    "MOTHERBOARD": "MB",
    "主機板": "MB",
    "RAM": "RAM",
    "MEMORY": "RAM",
    "記憶體": "RAM",
    "SSD": "SSD",
    "固態硬碟": "SSD",
    "PSU": "PSU",
    "POWER": "PSU",
    "POWERSUPPLY": "PSU",
    "電源供應器": "PSU",
    "電供": "PSU",
    "CASE": "CASE",
    "CHASSIS": "CASE",
    "機殼": "CASE",
}


def _normalize_string_list(values: list[str] | tuple[str, ...] | set[str] | None) -> list[str]:
    if not values:
        return []

    normalized: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = str(raw).strip()
        if not value or value in seen:
            continue
        normalized.append(value)
        seen.add(value)
    return normalized


def _normalize_category(value: object) -> str | None:
    token = " ".join(str(value).strip().split())
    if not token:
        return None
    normalized = token.upper().replace("-", "").replace("_", "").replace("/", "").replace(" ", "")
    alias = _CATEGORY_ALIASES.get(normalized) or _CATEGORY_ALIASES.get(token.upper())
    if alias in _ALLOWED_CATEGORIES:
        return alias
    return None


def _normalize_choice(value: object, mapping: dict[str, str]) -> str | None:
    token = " ".join(str(value).strip().split())
    if not token:
        return None
    return mapping.get(token.lower())


class ChatMessage(BaseModel):
    role: ChatRole
    content: str


class NormalizedDemand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_mode: NormalizedRequestMode = "unknown"
    categories: list[str] = Field(default_factory=list)
    usage_profile: NormalizedUsageProfile = "unknown"
    budget_max: int | None = Field(default=None, ge=0)
    budget_target: int | None = Field(default=None, ge=0)
    budget_flex_pct: float | None = Field(default=None, ge=0, le=1)
    preferred_cpu_vendor: Literal["AMD", "Intel"] | None = None
    preferred_gpu_vendor: Literal["NVIDIA", "AMD", "Intel"] | None = None
    size_preference: NormalizedSizePreference | None = None
    brand_preference_hard: list[str] = Field(default_factory=list)
    brand_preference_soft: list[str] = Field(default_factory=list)
    disallowed_brands: list[str] = Field(default_factory=list)
    must_have_features: list[str] = Field(default_factory=list)
    avoid_features: list[str] = Field(default_factory=list)
    allow_bundle: bool = False
    allow_board_bundle: bool = False
    allow_workstation_gpu: bool = False
    existing_parts: list[str] = Field(default_factory=list)
    upgrade_target_parts: list[str] = Field(default_factory=list)
    explanation_style: NormalizedExplanationStyle = "normal"
    missing_information: list[str] = Field(default_factory=list)
    normalization_confidence: float | None = Field(default=None, ge=0, le=1)
    normalization_source: NormalizationSource = "rule_fallback"
    query_focus: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _coerce_choices(cls, raw: Any) -> Any:
        if not isinstance(raw, dict):
            return raw
        normalized = dict(raw)
        choice_fields = {
            "request_mode": {
                "single_part": "single_part",
                "singlepart": "single_part",
                "build": "build",
                "upgrade": "upgrade",
                "unknown": "unknown",
            },
            "usage_profile": {
                "gaming": "gaming",
                "office": "office",
                "creator": "creator",
                "workstation": "workstation",
                "mixed": "mixed",
                "unknown": "unknown",
            },
            "explanation_style": {
                "brief": "brief",
                "normal": "normal",
                "detailed": "detailed",
            },
            "size_preference": {
                "itx": "ITX",
                "mini-itx": "ITX",
                "matx": "mATX",
                "m-atx": "mATX",
                "micro-atx": "mATX",
                "atx": "ATX",
                "unknown": "unknown",
            },
            "preferred_cpu_vendor": {
                "amd": "AMD",
                "intel": "Intel",
            },
            "preferred_gpu_vendor": {
                "nvidia": "NVIDIA",
                "amd": "AMD",
                "intel": "Intel",
            },
            "normalization_source": {
                "ai_structured": "ai_structured",
                "ai_repaired_json": "ai_repaired_json",
                "rule_fallback": "rule_fallback",
            },
        }
        for field_name, mapping in choice_fields.items():
            if field_name not in normalized:
                continue
            coerced = _normalize_choice(normalized.get(field_name), mapping)
            if coerced is not None:
                normalized[field_name] = coerced
        return normalized

    @model_validator(mode="after")
    def _normalize_fields(self) -> "NormalizedDemand":
        categories: list[str] = []
        seen_categories: set[str] = set()
        for raw in self.categories:
            category = _normalize_category(raw)
            if category is None or category in seen_categories:
                continue
            categories.append(category)
            seen_categories.add(category)
        self.categories = categories

        self.brand_preference_hard = _normalize_string_list(self.brand_preference_hard)
        self.brand_preference_soft = _normalize_string_list(self.brand_preference_soft)
        self.disallowed_brands = _normalize_string_list(self.disallowed_brands)
        self.must_have_features = _normalize_string_list(self.must_have_features)
        self.avoid_features = _normalize_string_list(self.avoid_features)
        self.existing_parts = _normalize_string_list(self.existing_parts)
        self.upgrade_target_parts = _normalize_string_list(self.upgrade_target_parts)
        self.missing_information = _normalize_string_list(self.missing_information)
        self.query_focus = _normalize_string_list(self.query_focus)

        if self.budget_max is not None and self.budget_target is None:
            self.budget_target = max(1, int(round(self.budget_max * 0.95)))

        if self.request_mode in {"build", "upgrade"}:
            self.allow_bundle = bool(self.allow_bundle)
            self.allow_board_bundle = bool(self.allow_board_bundle)
            self.allow_workstation_gpu = bool(self.allow_workstation_gpu)

        return self


class ContextPackItem(BaseModel):
    part_id: str
    category: str
    display_name: str
    key_specs: dict[str, SpecValue]
    price: float | None = None
    source: str
    source_url: str
    snapshot_id: str | None = None
    run_id: str | None = None

    @model_validator(mode="after")
    def _validate_lineage(self) -> "ContextPackItem":
        if self.snapshot_id or self.run_id:
            return self
        raise ValueError("ContextPackItem requires snapshot_id or run_id")


class ContextPack(BaseModel):
    items: list[ContextPackItem]
    context_pack_hash: str | None = None


class P3ContextPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str
    hash: str
    meta: dict[str, Any] | None = None


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    messages: list[ChatMessage] | None = None
    user_text: str | None = None
    history: list[ChatMessage] = Field(default_factory=list)
    demand: dict[str, Any] | str | None = None
    context_pack: ContextPack | None = None

    @model_validator(mode="after")
    def _validate_input_modes(self) -> "ChatRequest":
        if self.messages:
            return self
        if self.user_text and self.user_text.strip():
            return self
        raise ValueError("ChatRequest requires messages or user_text")


class ChatResponse(BaseModel):
    request_id: str
    provider: str
    model: str
    text: str
    latency_ms: int
    error_type: str | None = None
    warnings: list[str] | None = None
    compressed_candidates: dict[str, list[ContextPackItem]] | None = None
    drop_log: dict[str, dict[str, Any]] | None = None
