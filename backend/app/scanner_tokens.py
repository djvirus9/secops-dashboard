"""Administration and authentication of single-project scanner credentials."""
from __future__ import annotations

from datetime import timedelta
import hashlib
import re
import secrets
import unicodedata
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select, update

from .access import Principal, audit_event, require_admin
from .accounts import _lock_accounts, normalize_projects, utcnow
from .db import SessionLocal
from .models import ScannerToken

router = APIRouter()
TOKEN_PREFIX = "secops_ingest_"
MAX_SCANNER_TOKENS = 1000
MAX_ACTIVE_SCANNER_TOKENS = 100


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _new_secret() -> tuple[str, str]:
    value = TOKEN_PREFIX + secrets.token_urlsafe(48)
    return value, _token_hash(value)


def _active(token: ScannerToken, now=None) -> bool:
    return token.revoked_at is None and token.expires_at > (now or utcnow())


def serialize_token(token: ScannerToken) -> dict:
    def timestamp(value):
        return value.isoformat() + "Z" if value is not None else None

    return {"id": token.id, "name": token.name, "project": token.project,
            "created_at": timestamp(token.created_at), "expires_at": timestamp(token.expires_at),
            "revoked_at": timestamp(token.revoked_at), "last_used_at": timestamp(token.last_used_at),
            "active": _active(token)}


def scanner_principal(value: str) -> Principal | None:
    """Return a scoped automation actor, never a user identity or raw credential."""
    if not re.fullmatch(r"secops_ingest_[A-Za-z0-9_-]{64}", value):
        return None
    digest = _token_hash(value)
    now = utcnow()
    with SessionLocal.begin() as db:
        token = db.scalar(select(ScannerToken).where(
            ScannerToken.token_hash == digest, ScannerToken.revoked_at.is_(None),
            ScannerToken.expires_at > now,
        ))
        if token is None:
            return None
        # Rotation/revocation may win after the read. Only the still-current
        # hash can record use and finish authenticating this request.
        used = db.execute(update(ScannerToken).where(
            ScannerToken.id == token.id, ScannerToken.token_hash == digest,
            ScannerToken.revoked_at.is_(None), ScannerToken.expires_at > now,
        ).values(last_used_at=now))
        if used.rowcount != 1:
            return None
        return Principal(None, f"scanner:{token.id}", "analyst", (token.project,), "scanner")


class TokenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=100)
    project: str = Field(max_length=255)
    expires_in_days: int = Field(90, ge=1, le=365, strict=True)

    @field_validator("name")
    @classmethod
    def visible_name(cls, value):
        if any(unicodedata.category(char).startswith("C") for char in value):
            raise ValueError("Token name must contain visible text without control characters")
        return value

    @field_validator("project")
    @classmethod
    def valid_project(cls, value):
        return normalize_projects([value])[0]


class TokenRotate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expires_in_days: int = Field(90, ge=1, le=365, strict=True)


def _check_active_quota(db, now) -> None:
    active = db.scalar(select(func.count()).select_from(ScannerToken).where(
        ScannerToken.revoked_at.is_(None), ScannerToken.expires_at > now,
    )) or 0
    if active >= MAX_ACTIVE_SCANNER_TOKENS:
        raise HTTPException(422, "Active scanner token limit reached; revoke an unused token first")


@router.get("/scanner-tokens")
def list_tokens(request: Request):
    require_admin(request)
    with SessionLocal() as db:
        tokens = db.scalars(select(ScannerToken).order_by(ScannerToken.created_at.desc(), ScannerToken.id)).all()
        return {"count": len(tokens), "results": [serialize_token(token) for token in tokens]}


@router.post("/scanner-tokens", status_code=201)
def create_token(payload: TokenCreate, request: Request):
    require_admin(request)
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        now = utcnow()
        total = db.scalar(select(func.count()).select_from(ScannerToken)) or 0
        if total >= MAX_SCANNER_TOKENS:
            raise HTTPException(422, "Scanner token record limit reached; rotate an existing token instead")
        _check_active_quota(db, now)
        secret, digest = _new_secret()
        token = ScannerToken(name=payload.name, project=payload.project, token_hash=digest,
                             created_at=now, expires_at=now + timedelta(days=payload.expires_in_days))
        db.add(token)
        db.flush()
        audit_event(db, request, "scanner_token.create", "scanner_token", token.id,
                    {"project": token.project, "expires_in_days": payload.expires_in_days})
        result = serialize_token(token)
    return {"token": secret, "scanner_token": result}


@router.post("/scanner-tokens/{token_id}/revoke")
def revoke_token(token_id: UUID, request: Request):
    require_admin(request)
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        token = db.get(ScannerToken, str(token_id))
        if token is None:
            raise HTTPException(404, "Scanner token not found")
        if token.revoked_at is None:
            token.revoked_at = utcnow()
            audit_event(db, request, "scanner_token.revoke", "scanner_token", token.id)
    return {"ok": True}


@router.post("/scanner-tokens/{token_id}/rotate")
def rotate_token(token_id: UUID, request: Request, payload: TokenRotate | None = None):
    require_admin(request)
    payload = payload or TokenRotate()
    with SessionLocal.begin() as db:
        # Serialize rotation/revocation and quota checks across every process.
        # If administrators rotate concurrently, the last committed secret wins.
        _lock_accounts(db)
        token = db.get(ScannerToken, str(token_id))
        if token is None:
            raise HTTPException(404, "Scanner token not found")
        now = utcnow()
        if not _active(token, now):
            _check_active_quota(db, now)
        secret, token.token_hash = _new_secret()
        token.expires_at = now + timedelta(days=payload.expires_in_days)
        token.revoked_at, token.last_used_at = None, None
        db.flush()
        audit_event(db, request, "scanner_token.rotate", "scanner_token", token.id,
                    {"expires_in_days": payload.expires_in_days})
        result = serialize_token(token)
    return {"token": secret, "scanner_token": result}
