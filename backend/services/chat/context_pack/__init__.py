# backend/services/chat/context_pack/__init__.py
from .retrieval import (
    CandidatePart,
    P1Demand,
    P1RetrievalResult,
    retrieve_topk_candidates,
)
from .compress import compress_candidates
from .render import (
    build_context_pack,
    canonicalize_text_for_hash,
    hash_context_pack,
)

__all__ = [
    "CandidatePart",
    "P1Demand",
    "P1RetrievalResult",
    "retrieve_topk_candidates",
    "compress_candidates",
    "build_context_pack",
    "canonicalize_text_for_hash",
    "hash_context_pack",
]
