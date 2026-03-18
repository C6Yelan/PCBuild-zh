# backend/services/chat/clients/__init__.py
from .openai_compat_client import OpenAICompatError, generate_openai_compat_text

__all__ = ["OpenAICompatError", "generate_openai_compat_text"]