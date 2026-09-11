"""Shared server-side identity, role and project authorization."""
from __future__ import annotations

import json
from dataclasses import dataclass

from fastapi import HTTPException, Request

from .models import AuditEvent


@dataclass(frozen=True)
class Principal:
    id: str | None
    username: str
    role: str
    projects: tuple[str, ...] | None
    kind: str = "user"


def principal(request: Request) -> Principal:
    value = getattr(request.state, "principal", None)
    if not isinstance(value, Principal):
        raise HTTPException(401, "Authentication required")
    return value


def project_filters(request: Request, column) -> list:
    identity = principal(request)
    return [] if identity.projects is None else [column.in_(identity.projects)]


def require_project(request: Request, project: str) -> None:
    identity = principal(request)
    if identity.projects is not None and project not in identity.projects:
        raise HTTPException(404, "Resource not found")


def require_write(request: Request) -> Principal:
    identity = principal(request)
    if identity.role not in {"admin", "analyst"}:
        raise HTTPException(403, "Write access required")
    return identity


def require_admin(request: Request) -> Principal:
    identity = principal(request)
    if identity.role != "admin":
        raise HTTPException(403, "Administrator access required")
    return identity


def require_user(request: Request) -> Principal:
    identity = principal(request)
    if identity.kind != "user" or not identity.id:
        raise HTTPException(403, "A user session is required")
    return identity


def audit_event(db, request: Request, action: str, object_type: str,
                object_id: str | None = None, details: dict | None = None) -> AuditEvent:
    identity = principal(request)
    event = AuditEvent(user_id=identity.id, actor=identity.username, action=action,
                       object_type=object_type, object_id=object_id,
                       details_json=json.dumps(details or {}))
    db.add(event)
    return event
