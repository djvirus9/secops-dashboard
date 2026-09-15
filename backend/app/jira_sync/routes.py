"""Project-scoped Jira progress and administrator-only identity mappings."""
from __future__ import annotations

import json
import re
from uuid import UUID
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from ..access import audit_event, project_filters, require_admin, require_write
from ..accounts import _lock_accounts
from ..db import SessionLocal
from ..models import Finding, User, _utcnow
from . import client
from .models import JiraIssueLink, JiraUserMapping
from .service import STATUS_TARGETS, account_for_assignee, discover_link, preview, serialize_link, workflow_snapshot

router = APIRouter()
NOTE = ("Jira progress is polled by the automation worker. The first observation establishes a baseline. "
        "Later Jira Done transitions request verification; they never verify a fix. "
        "Remote ownership never grants project access.")


class MappingPut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jira_account_id: str = Field(min_length=1, max_length=128)
    active: bool = Field(default=True, strict=True)

    @field_validator("jira_account_id")
    @classmethod
    def account_id(cls, value):
        if not re.fullmatch(client.ACCOUNT_PATTERN, value):
            raise ValueError("Use a Jira account ID, not an email address or URL")
        return value


class PushRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: Literal["status", "assignee"]
    expected_local_status: str = Field(min_length=1, max_length=30)
    expected_local_assignee: str | None = Field(max_length=255)
    expected_remote_updated_at: str = Field(min_length=1, max_length=64)


def _finding(db, request, finding_id, *, lock=False):
    filters = [Finding.id == str(finding_id), *project_filters(request, Finding.project)]
    if lock:
        # A real UPDATE serializes queueing with local triage even on SQLite.
        db.execute(update(Finding).where(*filters).values(status=Finding.status))
    finding = db.scalar(select(Finding).where(*filters))
    if finding is None:
        raise HTTPException(404, "Finding not found")
    return finding


def _configuration():
    if not client.enabled():
        raise HTTPException(503, "Enable JIRA_SYNC_ENABLED on the server and run the automation worker first")
    try:
        return client.settings()
    except client.JiraError as exc:
        raise HTTPException(503, str(exc)) from exc


def _queue_link(db, finding, config):
    row = discover_link(db, finding.id, config)
    if row is None:
        raise HTTPException(409, "No successful Jira delivery exists for this finding and configured tenant")
    if row.base_url != config.base_url:
        raise HTTPException(409, "This issue belongs to a different Jira tenant; restore its server configuration")
    if row.status in {"queued", "syncing"}:
        raise HTTPException(409, "A Jira operation is already queued or running")
    return row


@router.get("/findings/{finding_id}/jira")
def finding_progress(finding_id: UUID, request: Request):
    with SessionLocal() as db:
        finding = _finding(db, request, finding_id)
        row = db.get(JiraIssueLink, finding.id)
        return {"configured": client.configured(), "enabled": client.enabled(),
                "link": serialize_link(row) if row else None, "push_preview": preview(db, finding), "note": NOTE}


@router.post("/findings/{finding_id}/jira/pull", status_code=202)
def queue_pull(finding_id: UUID, request: Request):
    require_write(request)
    config = _configuration()
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        finding = _finding(db, request, finding_id, lock=True)
        row = _queue_link(db, finding, config)
        row.status, row.operation, row.pending_json = "queued", "pull", "{}"
        row.next_sync_at, row.updated_at, row.attempts = _utcnow(), _utcnow(), 0
        row.last_error = None
        audit_event(db, request, "jira.pull.queue", "finding", finding.id, {"issue_key": row.issue_key})
    return {"ok": True, "message": "Jira progress pull queued"}


@router.post("/findings/{finding_id}/jira/push", status_code=202)
def queue_push(finding_id: UUID, payload: PushRequest, request: Request):
    actor = require_write(request)
    config = _configuration()
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        finding = _finding(db, request, finding_id, lock=True)
        row = _queue_link(db, finding, config)
        if row.remote_updated_at is None or row.last_synced_at is None:
            raise HTTPException(409, "Pull Jira progress before approving a push")
        if row.status == "needs_review":
            raise HTTPException(409, "Inspect Jira and pull progress before approving another push")
        if (finding.status != payload.expected_local_status or finding.assignee != payload.expected_local_assignee
                or row.remote_updated_at != payload.expected_remote_updated_at):
            raise HTTPException(409, "Finding or Jira progress changed; refresh and review the push preview")
        pending = {"snapshot": workflow_snapshot(db, finding), "actor": actor.username, "user_id": actor.id,
                   "remote": {"status_id": row.remote_status_id, "assignee_id": row.remote_assignee_id,
                              "updated_at": row.remote_updated_at}}
        if payload.field == "status":
            category = STATUS_TARGETS.get(finding.status)
            if category is None:
                raise HTTPException(422, "Only open, investigating, or verification-pending status can be pushed")
            pending["category"] = category
        else:
            try:
                pending["account_id"] = account_for_assignee(db, finding)
            except client.JiraError as exc:
                raise HTTPException(422, str(exc)) from exc
        row.status, row.operation = "queued", "push_" + payload.field
        row.pending_json, row.attempts, row.last_error = json.dumps(pending), 0, None
        row.next_sync_at, row.updated_at = _utcnow(), _utcnow()
        audit_event(db, request, "jira.push.queue", "finding", finding.id,
                    {"issue_key": row.issue_key, "field": payload.field,
                     "local_status": finding.status, "local_assignee": finding.assignee})
    return {"ok": True, "message": f"Approved Jira {payload.field} push queued"}


@router.get("/jira-sync")
def sync_status(request: Request, limit: int = 50, offset: int = 0):
    require_admin(request)
    limit, offset = max(1, min(limit, 200)), max(0, offset)
    with SessionLocal() as db:
        count = db.scalar(select(func.count()).select_from(JiraIssueLink)) or 0
        rows = db.scalars(select(JiraIssueLink).order_by(JiraIssueLink.updated_at.desc(), JiraIssueLink.finding_id)
                          .offset(offset).limit(limit)).all()
        return {"enabled": client.enabled(), "configured": client.configured(),
                "interval_minutes": client.interval_minutes(), "count": count, "offset": offset,
                "results": [serialize_link(row) for row in rows], "note": NOTE}


@router.get("/jira-sync/mappings")
def list_mappings(request: Request):
    require_admin(request)
    with SessionLocal() as db:
        rows = db.execute(select(JiraUserMapping, User.username).join(User, JiraUserMapping.user_id == User.id)
                          .order_by(User.username).limit(2000)).all()
        return {"results": [{"user_id": row.user_id, "username": username,
                              "jira_account_id": row.jira_account_id, "active": row.active}
                             for row, username in rows]}


@router.put("/jira-sync/mappings/{user_id}")
def put_mapping(user_id: UUID, payload: MappingPut, request: Request):
    require_admin(request)
    try:
        with SessionLocal.begin() as db:
            _lock_accounts(db)
            user = db.get(User, str(user_id))
            if user is None:
                raise HTTPException(404, "User not found")
            if payload.active and (not user.active or user.role not in {"admin", "analyst"}):
                raise HTTPException(422, "Map an active administrator or analyst account")
            row = db.get(JiraUserMapping, user.id)
            if row is None:
                row = JiraUserMapping(user_id=user.id, jira_account_id=payload.jira_account_id)
                db.add(row)
            row.jira_account_id, row.active, row.updated_at = payload.jira_account_id, payload.active, _utcnow()
            audit_event(db, request, "jira.mapping.update", "user", user.id,
                        {"jira_account_id": row.jira_account_id, "active": row.active})
            db.flush()
            return {"mapping": {"user_id": user.id, "username": user.username,
                                "jira_account_id": row.jira_account_id, "active": row.active}}
    except IntegrityError as exc:
        raise HTTPException(409, "This Jira account is already mapped to a local user") from exc
