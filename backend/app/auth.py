from __future__ import annotations

import os
from fastapi import Request
from fastapi.responses import JSONResponse

_UNPROTECTED = {"/health", "/docs", "/openapi.json", "/redoc"}


async def api_key_middleware(request: Request, call_next):
    api_key = os.environ.get("API_KEY")
    if api_key and request.url.path not in _UNPROTECTED:
        provided = request.headers.get("X-API-Key", "")
        if provided != api_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing API key"},
            )
    return await call_next(request)
