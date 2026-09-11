"""Administrator-managed, immutable repository-to-project mappings."""
from __future__ import annotations

import json
import os
import re
from datetime import timedelta
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select

from ..access import audit_event, require_admin
from ..accounts import _lock_accounts, normalize_projects
from ..db import SessionLocal
from ..models import _utcnow
from .models import GitHubConnection, GitHubSyncRun

router = APIRouter()
MAX_CONNECTIONS = 100


def configured() -> bool:
    return bool(os.environ.get("GITHUB_SYNC_TOKEN"))


def timestamp(value):
    return value.isoformat() + "Z" if value else None


def serialize_connection(row):
    return {"id": row.id, "repository": row.repository, "project": row.project,
            "sources": json.loads(row.sources_json), "enabled": row.enabled,
            "interval_minutes": row.interval_minutes, "status": row.status,
            "next_sync_at": timestamp(row.next_sync_at), "last_synced_at": timestamp(row.last_synced_at),
            "last_error": row.last_error}


class ConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    repository: str = Field(min_length=3, max_length=140)
    project: str = Field(max_length=255)
    sources: list[Literal["code_scanning", "dependabot"]] = Field(min_length=1, max_length=2)
    interval_minutes: int = Field(default=60, ge=15, le=1440, strict=True)

    @field_validator("repository")
    @classmethod
    def repository_name(cls, value):
        # GitHub Cloud only. Slashes, escapes, URL syntax and dot segments cannot
        # become an outbound destination or alter the API path.
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}", value):
            raise ValueError("Use a GitHub repository name in owner/repo format")
        if value.split("/")[1] in {".", ".."}:
            raise ValueError("Invalid repository name")
        return value.lower()

    @field_validator("project")
    @classmethod
    def project_name(cls, value):
        return normalize_projects([value])[0]

    @field_validator("sources")
    @classmethod
    def unique_sources(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("Select each alert source once")
        return sorted(value)


class ConnectionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = Field(default=None, strict=True)
    interval_minutes: int | None = Field(default=None, ge=15, le=1440, strict=True)


def get_connection(db, connection_id):
    row = db.get(GitHubConnection, str(connection_id))
    if row is None:
        raise HTTPException(404, "GitHub connection not found")
    return row


@router.get("/github-sync")
def list_connections(request: Request):
    require_admin(request)
    with SessionLocal() as db:
        rows = db.scalars(select(GitHubConnection).order_by(GitHubConnection.repository)).all()
        return {"configured": configured(), "count": len(rows),
                "results": [serialize_connection(row) for row in rows]}


@router.post("/github-sync", status_code=201)
def create_connection(payload: ConnectionCreate, request: Request):
    require_admin(request)
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        if db.scalar(select(GitHubConnection.id).where(GitHubConnection.repository == payload.repository)):
            raise HTTPException(409, "This repository already has a connection")
        if (db.scalar(select(func.count()).select_from(GitHubConnection)) or 0) >= MAX_CONNECTIONS:
            raise HTTPException(422, "GitHub connection limit reached")
        row = GitHubConnection(repository=payload.repository, project=payload.project,
                               sources_json=json.dumps(payload.sources), interval_minutes=payload.interval_minutes)
        db.add(row)
        db.flush()
        audit_event(db, request, "github_sync.create", "github_connection", row.id,
                    {"repository": row.repository, "project": row.project, "sources": payload.sources})
        result = serialize_connection(row)
    return {"connection": result}


@router.patch("/github-sync/{connection_id}")
def update_connection(connection_id: UUID, payload: ConnectionUpdate, request: Request):
    require_admin(request)
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        row = get_connection(db, connection_id)
        now = _utcnow()
        if payload.interval_minutes is not None:
            row.interval_minutes = payload.interval_minutes
            if row.status not in {"queued", "syncing"}:
                row.next_sync_at = now + timedelta(minutes=row.interval_minutes)
        if payload.enabled is not None and payload.enabled != row.enabled:
            row.enabled = payload.enabled
            if not row.enabled:
                if row.claim_token:
                    run = db.get(GitHubSyncRun, row.claim_token)
                    if run and run.status == "syncing":
                        run.status, run.completed_at, run.error = "cancelled", now, "Connection paused"
                row.claim_token, row.claimed_at, row.status = None, None, "idle"
            else:
                row.next_sync_at, row.status = now, "queued"
        row.updated_at = now
        audit_event(db, request, "github_sync.update", "github_connection", row.id,
                    payload.model_dump(exclude_none=True))
        db.flush()
        result = serialize_connection(row)
    return {"connection": result}


@router.post("/github-sync/{connection_id}/sync", status_code=202)
def queue_sync(connection_id: UUID, request: Request):
    require_admin(request)
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        row = get_connection(db, connection_id)
        if not configured():
            raise HTTPException(503, "Configure GITHUB_SYNC_TOKEN on the server and restart the app first")
        if not row.enabled:
            raise HTTPException(409, "Enable the connection before requesting a sync")
        if row.status in {"queued", "syncing"}:
            raise HTTPException(409, "A sync is already queued or running")
        row.status, row.next_sync_at, row.updated_at = "queued", _utcnow(), _utcnow()
        audit_event(db, request, "github_sync.queue", "github_connection", row.id)
    return {"ok": True, "message": "Sync queued"}


@router.get("/github-sync/{connection_id}/runs")
def list_runs(connection_id: UUID, request: Request):
    require_admin(request)
    with SessionLocal() as db:
        get_connection(db, connection_id)
        rows = db.scalars(select(GitHubSyncRun).where(GitHubSyncRun.connection_id == str(connection_id))
                          .order_by(GitHubSyncRun.started_at.desc(), GitHubSyncRun.id.desc()).limit(100)).all()
        return {"results": [{"id": row.id, "status": row.status, "started_at": timestamp(row.started_at),
                             "completed_at": timestamp(row.completed_at), "imported": row.imported,
                             "new_findings": row.new_findings, "updated": row.updated, "error": row.error}
                            for row in rows]}
