# backend/services/chat/clients/genai_client.py
from functools import lru_cache

from google import genai

from backend.core.settings import get_settings


@lru_cache(maxsize=1)
def get_genai_client() -> genai.Client:
    """
    取得 Gemini client（以快取避免每次 request 都初始化）。
    SDK 也支援從環境變數讀取 API key；此處改由 Settings 統一管理。
    """
    api_key = get_settings().genai_api_key()
    if api_key:
        return genai.Client(api_key=api_key)
    return genai.Client()
