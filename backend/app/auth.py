from __future__ import annotations

import logging
import os
import secrets

from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

# Only probes that must remain reachable without credentials belong here.
# API documentation intentionally remains protected because it describes the
# complete administrative API surface.
_UNPROTECTED = {"/health", "/ready"}
_TRUE_VALUES = {"1", "true", "yes", "on"}


def _insecure_no_auth_enabled() -> bool:
    return os.environ.get("ALLOW_INSECURE_NO_AUTH", "").strip().lower() in _TRUE_VALUES


async def api_key_middleware(request: Request, call_next):
    """Protect API routes with a fail-closed, constant-time API-key check.

    Use the raw ASGI path for the allowlist. Reconstructing the path through
    ``request.url`` can be influenced by malformed Host headers in vulnerable
    Starlette versions and previously allowed authentication bypasses.
    """

    path = request.scope.get("path", "")
    if path in _UNPROTECTED:
        return await call_next(request)

    expected = os.environ.get("API_KEY", "")
    if not expected:
        if _insecure_no_auth_enabled():
            return await call_next(request)

        logger.error("Protected request rejected because API_KEY is not configured")
        return JSONResponse(
            status_code=503,
            content={"detail": "API authentication is not configured"},
            headers={"Cache-Control": "no-store"},
        )

    provided = request.headers.get("X-API-Key", "")
    if not provided or not secrets.compare_digest(provided, expected):
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid or missing API key"},
            headers={"Cache-Control": "no-store"},
        )

    return await call_next(request)
