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
_INGEST_ONLY = {("POST", "/ingest/signal"), ("POST", "/import/scan")}
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
    if path in _UNPROTECTED or request.method.upper() == "OPTIONS":
        return await call_next(request)

    admin_key = os.environ.get("API_KEY", "")
    if not admin_key:
        if _insecure_no_auth_enabled():
            request.state.auth_scope = "insecure-development"
            request.state.auth_subject = "development"
            return await call_next(request)

        logger.error("Protected request rejected because API_KEY is not configured")
        return JSONResponse(
            status_code=503,
            content={"detail": "API authentication is not configured"},
            headers={"Cache-Control": "no-store"},
        )

    provided = request.headers.get("X-API-Key", "")
    ingest_key = os.environ.get("INGEST_API_KEY", "")
    if ingest_key and secrets.compare_digest(ingest_key, admin_key):
        logger.error("Protected request rejected because API key scopes overlap")
        return JSONResponse(
            status_code=503,
            content={"detail": "API key scopes are misconfigured"},
            headers={"Cache-Control": "no-store"},
        )

    if provided and secrets.compare_digest(provided, admin_key):
        request.state.auth_scope = "admin"
        request.state.auth_subject = (
            request.headers.get("X-SecOps-User", "").strip()[:255] or "api-admin"
        )
        return await call_next(request)

    route = (request.method.upper(), path)
    if (
        route in _INGEST_ONLY
        and ingest_key
        and provided
        and secrets.compare_digest(provided, ingest_key)
    ):
        request.state.auth_scope = "ingest"
        request.state.auth_subject = "scanner"
        return await call_next(request)

    return JSONResponse(
        status_code=401,
        content={"detail": "Invalid, missing, or insufficiently scoped API key"},
        headers={"Cache-Control": "no-store"},
    )
