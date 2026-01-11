# backend/app.py
import os
from ipaddress import ip_address, ip_network

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from backend.api.router import api_router
from backend.core.settings import get_settings
from backend.core.docs_gate import DocsGateMiddleware

# ===== App & CORS =====
app = FastAPI()
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(DocsGateMiddleware)

# ===== 掛載各個 router =====
app.include_router(api_router)

# ===== 靜態網站：最後才 mount，避免吃掉 API 路由 =====
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(ROOT_DIR, "web")
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="site")
