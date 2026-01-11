# backend/core/routes.py
from fastapi import FastAPI

from backend.api.router import api_router


def include_api_routes(app: FastAPI) -> None:
    app.include_router(api_router)
