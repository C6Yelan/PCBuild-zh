# backend/tools/db/staging_ingest_models.py
"""Compatibility shim for canonical crawler staging-ingest models."""

from backend.tools.db.staging_ingest_support.models import StageIngestPayload, StagingCounts

__all__ = ["StageIngestPayload", "StagingCounts"]
