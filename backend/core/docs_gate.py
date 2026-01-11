# backend/core/docs_gate.py
from ipaddress import ip_address, ip_network

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# 只允許內網查看 /docs /redoc /openapi.json
_PRIVATE_NETS = [
    ip_network("127.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]


class DocsGateMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        p = request.url.path
        if p in ("/docs", "/redoc", "/openapi.json"):
            # 經 Cloudflare Tunnel 進來會帶 CF-Connecting-IP => 視為外網，直接 404
            if request.headers.get("CF-Connecting-IP"):
                return Response(status_code=404)

            # 內網直連則檢查來源 IP
            host = request.client.host or ""
            try:
                ip = ip_address(host)
                if not any(ip in n for n in _PRIVATE_NETS):
                    return Response(status_code=404)
            except ValueError:
                return Response(status_code=404)

        return await call_next(request)
