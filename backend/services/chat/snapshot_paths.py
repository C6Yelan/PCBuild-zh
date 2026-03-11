# backend/services/chat/snapshot_paths.py
"""Snapshot root and request-directory resolution helpers for chat artifacts."""

from __future__ import annotations

from pathlib import Path

from backend.services.chat.config import AISettings

_SNAPSHOT_DIR_FALLBACK = "/tmp/pcbuild_ai_raw_snapshots"


def snapshot_root(settings: AISettings) -> Path:
    raw_dir = getattr(settings, "ai_raw_snapshot_dir", _SNAPSHOT_DIR_FALLBACK)
    normalized = str(raw_dir or _SNAPSHOT_DIR_FALLBACK).strip() or _SNAPSHOT_DIR_FALLBACK
    return Path(normalized)


def snapshot_dir(settings: AISettings, request_id: str) -> Path:
    return snapshot_root(settings) / request_id
