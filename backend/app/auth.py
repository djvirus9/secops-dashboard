from __future__ import annotations

import logging
import os
import secrets

from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi import HTTPException
from starlette.concurrency import run_in_threadpool

from .access import Principal, require_admin
from .accounts import COOKIE_NAME, require_origin, session_principal
from .scanner_tokens import scanner_principal

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
    method = request.method.upper()
    if path in _UNPROTECTED or method == "OPTIONS" or (method, path) == ("POST", "/auth/login"):
        return await call_next(request)

    admin_key = os.environ.get("API_KEY", "")
    if not admin_key:
        if _insecure_no_auth_enabled():
            request.state.auth_scope = "insecure-development"
            request.state.auth_subject = "development"
            request.state.principal = Principal(None, "development", "admin", None, "api")
            return await call_next(request)

        logger.error("Protected request rejected because API_KEY is not configured")
        return JSONResponse(
            status_code=503,
            content={"detail": "API authentication is not configured"},
            headers={"Cache-Control": "no-store"},
        )

    provided = request.headers.get("X-API-Key", "")
    ingest_key = os.environ.get("INGEST_API_KEY", "")
    if ingest_key and secrets.compare_digest(ingest_key.encode("utf-8"), admin_key.encode("utf-8")):
        logger.error("Protected request rejected because API key scopes overlap")
        return JSONResponse(
            status_code=503,
            content={"detail": "API key scopes are misconfigured"},
            headers={"Cache-Control": "no-store"},
        )

    identity = None
    if provided:
        if secrets.compare_digest(provided.encode("utf-8"), admin_key.encode("utf-8")):
            identity = Principal(None, "api-admin", "admin", None, "api")
        elif (method, path) in _INGEST_ONLY and ingest_key and secrets.compare_digest(
            provided.encode("utf-8"), ingest_key.encode("utf-8")
        ):
            identity = Principal(None, "scanner", "analyst", None, "scanner")
        elif (method, path) in _INGEST_ONLY:
            identity = await run_in_threadpool(scanner_principal, provided)
    else:
        token = request.cookies.get(COOKIE_NAME, "")
        if token:
            session = await run_in_threadpool(session_principal, token)
            if session:
                identity, request.state.session_id = session
    if identity is None:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"},
                            headers={"Cache-Control": "no-store"})
    request.state.principal = identity
    request.state.auth_subject = identity.username
    request.state.auth_scope = "ingest" if identity.kind == "scanner" else identity.role
    try:
        if identity.kind == "user" and method not in {"GET", "HEAD", "OPTIONS"}:
            require_origin(request)
        if path in {"/docs", "/redoc", "/openapi.json"} or any(
            path == prefix or path.startswith(prefix + "/")
            for prefix in ("/users", "/notifications", "/integrations", "/docs", "/scanner-tokens")
        ):
            require_admin(request)
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail},
                            headers={"Cache-Control": "no-store"})
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response
