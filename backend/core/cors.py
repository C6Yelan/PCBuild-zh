# backend/core/cors.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.core.settings import get_settings


def add_cors_middleware(app: FastAPI) -> None:
    settings = get_settings()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
