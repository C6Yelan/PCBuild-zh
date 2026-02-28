# backend/services/chat/service.py
import logging

from sqlalchemy.orm import Session

from backend.schemas.chat import Turn
from backend.services.catalog import retrieve_topk_candidates
from backend.services.chat.clients.genai_client import get_genai_client
from backend.services.chat.context_pack import CompressedPart, DropLogItem, compress_candidates
from backend.services.chat.contracts import P1Demand
from backend.services.chat.prompt import build_prompt

_DEFAULT_P1_CATEGORIES: tuple[str, ...] = ("CPU", "MB", "GPU", "RAM")
_DEFAULT_P1_TOP_K = 5
_DEFAULT_P1_ENV = "prod"
logger = logging.getLogger(__name__)


def generate_chat_reply(message: str, history: list[Turn], db: Session | None = None) -> str:
    compressed_candidates: dict[str, list[CompressedPart]] = {}
    if db is not None:
        compressed_candidates, drop_log = _retrieve_and_compress_candidates(db=db)
        logger.debug(
            "chat_context_candidates categories=%s parts=%s drop_log_items=%s dropped_keys=%s",
            sorted(compressed_candidates.keys()),
            sum(len(parts) for parts in compressed_candidates.values()),
            len(drop_log),
            sum(len(item.dropped_keys) for item in drop_log),
        )
        if drop_log:
            logger.debug(
                "chat_context_drop_log=%s",
                [item.model_dump(mode="json") for item in drop_log],
            )

    client = get_genai_client()
    prompt = build_prompt(
        message=message,
        history=history,
        compressed_candidates=compressed_candidates,
    )
    response = client.generate_text(prompt=prompt)
    return response.text


def _retrieve_and_compress_candidates(
    *,
    db: Session,
) -> tuple[dict[str, list[CompressedPart]], list[DropLogItem]]:
    try:
        retrieval_result = retrieve_topk_candidates(
            db,
            categories=list(_DEFAULT_P1_CATEGORIES),
            top_k=_DEFAULT_P1_TOP_K,
            demand=P1Demand(),
            env=_DEFAULT_P1_ENV,
        )
        return compress_candidates(retrieval_result.candidates)
    except Exception:
        logger.exception("chat_context_pipeline_failed")
        return {}, []
