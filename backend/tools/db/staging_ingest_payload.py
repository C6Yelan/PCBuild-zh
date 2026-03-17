# backend/tools/db/staging_ingest_payload.py
"""Compatibility shim for canonical T7 staging-ingest payload helpers."""

from backend.tools.db.staging_ingest_support.payload import load_stage_ingest_payload

__all__ = ["load_stage_ingest_payload"]
