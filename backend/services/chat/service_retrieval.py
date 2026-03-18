"""Compatibility shim for chat retrieval helpers."""

from __future__ import annotations

from backend.services.chat.service.retrieval import (
    RetrievalArtifacts,
    empty_retrieval_artifacts,
    prepare_retrieval_artifacts,
)

__all__ = [
    "RetrievalArtifacts",
    "empty_retrieval_artifacts",
    "prepare_retrieval_artifacts",
]
