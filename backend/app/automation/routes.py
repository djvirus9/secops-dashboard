from __future__ import annotations

import os
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, update

from ..access import audit_event, project_filters, require_admin, require_project, require_write
from ..accounts import _lock_accounts
from ..db import SessionLocal
from ..models import ProjectProfile, _utcnow
from .models import AutomationPolicy, OperationalAlert
from .service import resolve_alert

router = APIRouter()


def _date(value):
    return value.isoformat() + "Z" if value else None


def serialize_policy(row):
    return {name: getattr(row, name) for name in (
        "project", "enabled", "warn_before_hours", "reminder_hours", "notify_slack", "last_error",
    )} | {name: _date(getattr(row, name)) for name in ("last_evaluated_at", "next_evaluation_at")}


def serialize_alert(row):
    return {name: getattr(row, name) for name in (
        "id", "project", "kind", "resource_id", "condition", "state", "title", "message",
        "owner", "team", "escalation_contact", "acknowledged_by",
    )} | {name: _date(getattr(row, name)) for name in (
        "first_seen_at", "last_seen_at", "resolved_at", "acknowledged_at",
    )}


class PolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    warn_before_hours: int = Field(24, ge=1, le=168, strict=True)
    reminder_hours: int = Field(24, ge=1, le=168, strict=True)
    notify_slack: bool = False


@router.get("/automation")
def automation(request: Request):
    with SessionLocal() as db:
        policies = db.scalars(select(AutomationPolicy).where(
            *project_filters(request, AutomationPolicy.project),
        ).order_by(AutomationPolicy.project)).all()
        return {"policies": [serialize_policy(row) for row in policies],
                "slack_configured": bool(os.environ.get("SLACK_WEBHOOK_URL"))}


@router.put("/automation/policies")
def set_policy(payload: PolicyInput, request: Request, project: str = Query(min_length=1, max_length=255)):
    require_admin(request)
    require_project(request, project)
    now = _utcnow()
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        if db.get(ProjectProfile, project) is None:
            raise HTTPException(422, "Create a project profile in Catalog first")
        # Serialize policy pauses/edits with the evaluator's policy claim.
        row = db.scalar(select(AutomationPolicy).where(AutomationPolicy.project == project).with_for_update())
        if row is None:
            row = AutomationPolicy(project=project, created_at=now)
            db.add(row)
        for field, value in payload.model_dump().items():
            setattr(row, field, value)
        row.updated_at = row.next_evaluation_at = now
        row.last_error = None
        if not row.enabled:
            for alert in db.scalars(select(OperationalAlert).where(
                OperationalAlert.project == project, OperationalAlert.state != "resolved",
            ).order_by(OperationalAlert.id).with_for_update()):
                resolve_alert(db, alert, now, reason="policy disabled")
        db.flush()
        audit_event(db, request, "automation.policy.update", "project", project, payload.model_dump())
        return {"policy": serialize_policy(row)}


@router.post("/automation/evaluate")
def queue_evaluation(request: Request, project: str = Query(min_length=1, max_length=255)):
    require_admin(request)
    require_project(request, project)
    with SessionLocal.begin() as db:
        changed = db.execute(update(AutomationPolicy).where(
            AutomationPolicy.project == project, AutomationPolicy.enabled.is_(True),
        ).values(next_evaluation_at=_utcnow()))
        if changed.rowcount != 1:
            raise HTTPException(409, "Enable an automation policy for this project first")
        audit_event(db, request, "automation.evaluate", "project", project)
    return {"ok": True}


@router.get("/automation/alerts")
def alerts(request: Request, state: Literal["active", "all", "resolved"] = "active",
           project: str | None = Query(None, max_length=255),
           kind: Literal["sla", "coverage"] | None = None, limit: int = 50, offset: int = 0):
    limit, offset = max(1, min(limit, 200)), max(0, offset)
    filters = project_filters(request, OperationalAlert.project)
    if state != "all":
        filters.append(OperationalAlert.state == "resolved" if state == "resolved"
                       else OperationalAlert.state != "resolved")
    if project is not None:
        filters.append(OperationalAlert.project == project)
    if kind:
        filters.append(OperationalAlert.kind == kind)
    with SessionLocal() as db:
        rows = db.scalars(select(OperationalAlert).where(*filters).order_by(
            OperationalAlert.last_seen_at.desc(), OperationalAlert.id,
        ).offset(offset).limit(limit)).all()
        count = db.scalar(select(func.count()).select_from(OperationalAlert).where(*filters)) or 0
        return {"count": count, "offset": offset, "page_count": len(rows),
                "results": [serialize_alert(row) for row in rows]}


@router.post("/automation/alerts/{alert_id}/acknowledge")
def acknowledge(alert_id: UUID, request: Request):
    actor = require_write(request)
    now = _utcnow()
    with SessionLocal.begin() as db:
        row = db.scalar(select(OperationalAlert).where(
            OperationalAlert.id == str(alert_id), *project_filters(request, OperationalAlert.project),
        ))
        if row is None:
            raise HTTPException(404, "Alert not found")
        if row.state == "resolved":
            raise HTTPException(409, "This alert has already cleared")
        if row.state == "open":
            result = db.execute(update(OperationalAlert).where(
                OperationalAlert.id == row.id, OperationalAlert.state == "open",
                OperationalAlert.generation == row.generation,
            ).values(state="acknowledged", acknowledged_at=now, acknowledged_by=actor.username))
            if result.rowcount != 1:
                raise HTTPException(409, "Alert changed; refresh before acknowledging")
            audit_event(db, request, "automation.alert.acknowledge", "operational_alert", row.id,
                        {"project": row.project, "generation": row.generation})
            db.refresh(row)
        return {"alert": serialize_alert(row)}
