"""Local accounts, revocable sessions and operator-only password recovery."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Literal

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError

from .access import Principal, audit_event, require_admin, require_user
from .db import SessionLocal
from .limits import positive_int_setting
from .models import AuditEvent, AuthLock, AuthThrottle, User, UserSession

router = APIRouter()
COOKIE_NAME = "secops_session"
PASSWORD_HASHER = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1,
                                 hash_len=32, salt_len=16, type=Type.ID)


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def normalize_username(value: str) -> str:
    value = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.@-]{0,99}", value):
        raise ValueError("Username must use 1-100 letters, digits, periods, underscores, @ or hyphens")
    return value


def validate_password(value: str) -> str:
    if not 15 <= len(value) <= 1024:
        raise ValueError("Password must contain 15-1024 characters")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Password must contain valid Unicode") from exc
    return value


def normalize_projects(value: list[str] | None) -> list[str] | None:
    if value is None:
        return None
    if len(value) > 500:
        raise ValueError("At most 500 project grants are allowed")
    result = []
    for project in value:
        project = project.strip()
        try:
            invalid = "\x00" in project or len(project) > 255 or len(project.encode("utf-8")) > 512
        except UnicodeError:
            invalid = True
        if invalid:
            raise ValueError("Project grants must be valid text of at most 255 characters and 512 UTF-8 bytes")
        if project not in result:
            result.append(project)
    return result


def user_projects(user: User) -> tuple[str, ...] | None:
    if user.role == "admin" or user.projects_json is None:
        return None
    try:
        values = json.loads(user.projects_json)
        if isinstance(values, list) and all(isinstance(value, str) for value in values):
            return tuple(values)
    except (ValueError, TypeError):
        pass
    return ()  # Corrupt grants fail closed.


def serialize_user(user: User) -> dict:
    projects = user_projects(user)
    return {"id": user.id, "username": user.username, "role": user.role,
            "projects": list(projects) if projects is not None else None, "active": user.active}


def _lock_accounts(db) -> None:
    insert = pg_insert if db.bind.dialect.name == "postgresql" else sqlite_insert
    db.execute(insert(AuthLock).values(id=1).on_conflict_do_nothing(index_elements=["id"]))
    # UPDATE acquires a transaction lock on PostgreSQL and SQLite alike. Every
    # account lifecycle operation uses it, including first-admin creation.
    db.execute(update(AuthLock).where(AuthLock.id == 1).values(id=1))


def revoke_sessions(db, user_id: str) -> None:
    db.execute(update(UserSession).where(UserSession.user_id == user_id,
                                        UserSession.revoked_at.is_(None)).values(revoked_at=utcnow()))


@lru_cache(maxsize=1)
def _dummy_password_hash() -> str:
    return PASSWORD_HASHER.hash(secrets.token_urlsafe(32))


def password_matches(encoded: str, password: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(encoded, password)
    except (VerificationError, InvalidHashError, UnicodeError):
        return False


def bootstrap_admin() -> None:
    username, password = os.getenv("DASHBOARD_USERNAME"), os.getenv("DASHBOARD_PASSWORD")
    if not username and not password:
        return  # API-only installations may omit the bootstrap pair.
    if not username or not password:
        raise RuntimeError("DASHBOARD_USERNAME and DASHBOARD_PASSWORD must be configured together")
    try:
        username = normalize_username(username)
        validate_password(password)
    except ValueError as exc:
        raise RuntimeError("Bootstrap account settings are invalid") from exc
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        if db.scalar(select(func.count()).select_from(User)):
            return
        user = User(username=username, password_hash=PASSWORD_HASHER.hash(password),
                    role="admin", projects_json=None, active=True)
        db.add(user)
        db.flush()
        db.add(AuditEvent(user_id=user.id, actor="bootstrap", action="user.bootstrap",
                          object_type="user", object_id=user.id, details_json="{}"))


def allowed_origins() -> set[str]:
    return {value.strip() for value in os.getenv("DASHBOARD_ORIGINS", "http://localhost:5000").split(",")
            if value.strip()}


def require_origin(request: Request) -> None:
    # Only configured exact origins are trusted. Host and proxy headers never
    # expand this boundary, and a missing Origin is rejected for cookie writes.
    if request.headers.get("origin", "") not in allowed_origins():
        raise HTTPException(403, "Request origin is not allowed")


def cookie_secure() -> bool:
    return os.getenv("SESSION_COOKIE_SECURE", "true").strip().lower() not in {"false", "0", "no", "off"}


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/", secure=cookie_secure(), httponly=True, samesite="strict")


def session_principal(token: str) -> tuple[Principal, str] | None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{64}", token):
        return None
    now = utcnow()
    idle_cutoff = now - timedelta(seconds=positive_int_setting("SESSION_IDLE_TIMEOUT_SECONDS", 1800))
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    with SessionLocal.begin() as db:
        result = db.execute(select(UserSession, User).join(User, User.id == UserSession.user_id).where(
            UserSession.token_hash == digest, UserSession.revoked_at.is_(None),
            UserSession.expires_at > now, UserSession.last_seen_at > idle_cutoff, User.active.is_(True),
        )).first()
        if not result:
            return None
        session, user = result
        if user.role not in {"admin", "analyst", "viewer"}:
            return None
        refreshed = db.execute(update(UserSession).where(
            UserSession.id == session.id, UserSession.revoked_at.is_(None),
            UserSession.expires_at > now, UserSession.last_seen_at > idle_cutoff,
        ).values(last_seen_at=now))
        if refreshed.rowcount != 1:
            return None
        return Principal(user.id, user.username, user.role, user_projects(user)), session.id


def _consume_login_attempt(username: str) -> None:
    """Bound global password work and per-account attempts, across workers.

    Keys are hashes, never raw account names or untrusted forwarded addresses.
    Counting all attempts avoids a success/reset race. Entries expire and the
    table has a hard cap, so random usernames cannot grow it without bound.
    """
    now = utcnow()
    throttled = False
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        db.execute(delete(AuthThrottle).where(AuthThrottle.updated_at < now - timedelta(minutes=15)))
        for label, limit, seconds in (("global", 40, 60), ("account:" + username, 10, 300)):
            key = hashlib.sha256(label.encode("utf-8")).hexdigest()
            row = db.get(AuthThrottle, key)
            if row is None:
                if (db.scalar(select(func.count()).select_from(AuthThrottle)) or 0) >= 1024:
                    throttled = True
                    break
                row = AuthThrottle(key=key, window_start=now, updated_at=now, failures=0)
                db.add(row)
            elif now >= row.window_start + timedelta(seconds=seconds):
                row.window_start, row.failures, row.blocked_until = now, 0, None
            row.failures += 1
            row.updated_at = now
            if row.failures > limit:
                row.blocked_until = row.window_start + timedelta(seconds=seconds)
                throttled = True
            db.flush()
    if throttled:
        raise HTTPException(429, "Unable to sign in; try again later", headers={"Retry-After": "300"})


class AccountModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(AccountModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


class UserCreate(AccountModel):
    username: str
    password: str
    role: Literal["admin", "analyst", "viewer"] = "viewer"
    projects: list[str] | None = Field(default_factory=list)

    _username = field_validator("username")(normalize_username)
    _password = field_validator("password")(validate_password)
    _projects = field_validator("projects")(normalize_projects)


class UserPatch(AccountModel):
    role: Literal["admin", "analyst", "viewer"] | None = None
    active: bool | None = None
    projects: list[str] | None = None
    password: str | None = None

    _projects = field_validator("projects")(normalize_projects)

    @field_validator("password")
    @classmethod
    def check_password(cls, value):
        return validate_password(value) if value is not None else None


class PasswordChange(AccountModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str
    _password = field_validator("new_password")(validate_password)


@router.post("/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    require_origin(request)
    try:
        username = normalize_username(payload.username)
    except ValueError:
        _consume_login_attempt("invalid-username")
        raise HTTPException(401, "Invalid username or password") from None
    _consume_login_attempt(username)
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))
        encoded = user.password_hash if user else _dummy_password_hash()
        valid = password_matches(encoded, payload.password)
        if not valid or not user or not user.active:
            raise HTTPException(401, "Invalid username or password")
        user_id = user.id
    now = utcnow()
    token = secrets.token_urlsafe(48)
    expires = now + timedelta(seconds=positive_int_setting("SESSION_TTL_SECONDS", 43200))
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        user = db.get(User, user_id)
        if not user or not user.active or user.password_hash != encoded:
            raise HTTPException(401, "Invalid username or password")
        # Retain at most ten live sessions per user; expired/revoked tokens need
        # no retention because audit events hold lifecycle history separately.
        db.execute(delete(UserSession).where(UserSession.user_id == user.id,
                                             (UserSession.expires_at <= now) | UserSession.revoked_at.is_not(None)))
        excess = db.scalars(select(UserSession.id).where(UserSession.user_id == user.id)
                            .order_by(UserSession.created_at.desc()).offset(9)).all()
        if excess:
            db.execute(delete(UserSession).where(UserSession.id.in_(excess)))
        session = UserSession(user_id=user.id, token_hash=hashlib.sha256(token.encode()).hexdigest(),
                              created_at=now, expires_at=expires, last_seen_at=now)
        db.add(session)
        db.flush()
        db.add(AuditEvent(user_id=user.id, actor=user.username, action="auth.login",
                          object_type="session", object_id=session.id, details_json="{}"))
        result = serialize_user(user)
    response.set_cookie(COOKIE_NAME, token, max_age=int((expires - now).total_seconds()),
                        expires=expires.replace(tzinfo=UTC), path="/", secure=cookie_secure(),
                        httponly=True, samesite="strict")
    response.headers["Cache-Control"] = "no-store"
    return {"user": result, "expires_at": expires.isoformat() + "Z"}


@router.get("/auth/me")
def me(request: Request):
    identity = require_user(request)
    with SessionLocal() as db:
        return {"user": serialize_user(db.get(User, identity.id))}


@router.post("/auth/logout")
def logout(request: Request, response: Response):
    identity = require_user(request)
    with SessionLocal.begin() as db:
        db.execute(update(UserSession).where(UserSession.id == request.state.session_id,
                                             UserSession.user_id == identity.id).values(revoked_at=utcnow()))
        audit_event(db, request, "auth.logout", "session", request.state.session_id)
    _clear_cookie(response)
    return {"ok": True}


@router.post("/auth/password")
def change_password(payload: PasswordChange, request: Request, response: Response):
    identity = require_user(request)
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        user = db.get(User, identity.id)
        if not password_matches(user.password_hash, payload.current_password):
            raise HTTPException(400, "Current password is incorrect")
        user.password_hash, user.updated_at = PASSWORD_HASHER.hash(payload.new_password), utcnow()
        revoke_sessions(db, user.id)
        audit_event(db, request, "user.password_changed", "user", user.id)
    _clear_cookie(response)
    return {"ok": True}


@router.get("/users")
def list_users(request: Request):
    require_admin(request)
    with SessionLocal() as db:
        users = db.scalars(select(User).order_by(User.username)).all()
        return {"count": len(users), "results": [serialize_user(user) for user in users]}


@router.post("/users", status_code=201)
def create_user(payload: UserCreate, request: Request):
    require_admin(request)
    try:
        with SessionLocal.begin() as db:
            _lock_accounts(db)
            user = User(username=payload.username, password_hash=PASSWORD_HASHER.hash(payload.password),
                        role=payload.role, active=True,
                        projects_json=None if payload.role == "admin" or payload.projects is None else json.dumps(payload.projects))
            db.add(user)
            db.flush()
            audit_event(db, request, "user.created", "user", user.id,
                        {"role": user.role, "projects": serialize_user(user)["projects"]})
            return {"user": serialize_user(user)}
    except IntegrityError as exc:
        raise HTTPException(409, "Username already exists") from exc


@router.patch("/users/{user_id}")
def update_user(user_id: str, payload: UserPatch, request: Request):
    require_admin(request)
    if not payload.model_fields_set or any(getattr(payload, field) is None for field in payload.model_fields_set - {"projects"}):
        raise HTTPException(400, "Provide a non-null account change")
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(404, "User not found")
        role = payload.role if payload.role is not None else user.role
        active = payload.active if payload.active is not None else user.active
        if user.role == "admin" and user.active and (role != "admin" or not active):
            admins = db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.active.is_(True)))
            if admins <= 1:
                raise HTTPException(409, "At least one active administrator must remain")
        user.role, user.active, user.updated_at = role, active, utcnow()
        if "projects" in payload.model_fields_set:
            user.projects_json = None if payload.projects is None else json.dumps(payload.projects)
        if role == "admin":
            user.projects_json = None
        if payload.password is not None:
            user.password_hash = PASSWORD_HASHER.hash(payload.password)
        revoke_sessions(db, user.id)
        audit_event(db, request, "user.updated", "user", user.id,
                    {"fields": sorted(payload.model_fields_set), "role": role, "active": active,
                     "projects": serialize_user(user)["projects"]})
        return {"user": serialize_user(user)}


def reset_password(username: str, password: str) -> None:
    """Local operator recovery; not registered as an HTTP endpoint."""
    username, password = normalize_username(username), validate_password(password)
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        user = db.scalar(select(User).where(User.username == username))
        if not user:
            raise ValueError("User not found")
        user.password_hash, user.updated_at = PASSWORD_HASHER.hash(password), utcnow()
        revoke_sessions(db, user.id)
        db.add(AuditEvent(user_id=user.id, actor="local-recovery", action="user.password_reset",
                          object_type="user", object_id=user.id, details_json="{}"))


def main() -> None:
    import argparse
    import getpass
    parser = argparse.ArgumentParser(description="Local account recovery (requires database access)")
    command = parser.add_subparsers(dest="command", required=True)
    reset = command.add_parser("reset-password")
    reset.add_argument("--username", required=True)
    args = parser.parse_args()
    password = getpass.getpass("New password: ")
    if password != getpass.getpass("Confirm new password: "):
        raise SystemExit("Passwords do not match")
    try:
        reset_password(args.username, password)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print("Password updated; existing sessions have been revoked")


if __name__ == "__main__":
    main()
