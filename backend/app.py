# backend/app.py
from fastapi import FastAPI

from backend.api.router import api_router
from backend.core.docs_gate import DocsGateMiddleware
from backend.core.static_site import mount_static_site
from backend.core.cors import add_cors_middleware

# ===== App & CORS =====
app = FastAPI()
add_cors_middleware(app)

app.add_middleware(DocsGateMiddleware)

# ===== 掛載各個 router =====
app.include_router(api_router)

# ===== 靜態網站：最後才 mount，避免吃掉 API 路由 =====
mount_static_site(app)