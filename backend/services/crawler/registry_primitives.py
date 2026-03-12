# backend/services/crawler/registry_primitives.py
"""Shared normalize and lookup primitives for crawler registries."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, MutableMapping
from typing import Final, TypeVar, cast

K = TypeVar("K")
V = TypeVar("V")

_MISSING: Final = object()


def normalize_registry_key(
    value: str | None,
    *,
    case: str = "identity",
    hyphen_to_underscore: bool = False,
    strip: bool = True,
) -> str:
    text = value or ""
    if strip:
        text = text.strip()
    if hyphen_to_underscore:
        text = text.replace("-", "_")
    if case == "lower":
        return text.lower()
    if case == "upper":
        return text.upper()
    if case == "identity":
        return text
    raise ValueError(f"unsupported case normalizer: {case!r}")


def lookup_registry_entry(
    registry: Mapping[K, V],
    key: K,
    *,
    default: V | object = _MISSING,
    missing_factory: Callable[[K], Exception] | None = None,
) -> V:
    value = registry.get(key, _MISSING)
    if value is not _MISSING:
        return cast(V, value)
    if default is not _MISSING:
        return cast(V, default)
    if missing_factory is not None:
        raise missing_factory(key)
    raise KeyError(key)


def register_aliases(registry: MutableMapping[str, V], aliases: Iterable[str], value: V) -> V:
    for alias in aliases:
        registry[alias] = value
    return value
