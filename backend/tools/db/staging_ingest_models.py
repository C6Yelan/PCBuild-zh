"""Compatibility shim for canonical T7 staging-ingest models."""

from backend.tools.db.staging_ingest_support.models import StageIngestPayload, StagingCounts

__all__ = ["StageIngestPayload", "StagingCounts"]
