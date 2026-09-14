"""Authenticated remediation policy, intelligence, and risk-acceptance routes."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select

from ..access import audit_event, principal, project_filters, require_admin, require_user
from ..db import SessionLocal
from ..accounts import normalize_projects
from ..models import Comment, Finding, IntelligenceSyncState, RemediationPolicy, _utcnow
from .service import DEFAULT_POLICY, SOURCES, ensure_sync_states, queue_sources, refresh_project


router = APIRouter()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyInput(StrictModel):
    project: str = Field("", max_length=255)
    critical_days: int = Field(7, ge=1, le=3650)
    high_days: int = Field(30, ge=1, le=3650)
    medium_days: int = Field(90, ge=1, le=3650)
    low_days: int = Field(180, ge=1, le=3650)
    info_days: int = Field(365, ge=1, le=3650)
    kev_days: int = Field(7, ge=1, le=365)

    @field_validator("project")
    @classmethod
    def valid_project(cls, value):
        return normalize_projects([value])[0]


class SyncRequest(StrictModel):
    sources: list[Literal["cisa_kev", "first_epss"]] = Field(
        default_factory=lambda: list(SOURCES), min_length=1, max_length=2,
    )


class SourceSettings(StrictModel):
    enabled: bool
    interval_hours: int = Field(24, ge=1, le=168)


class RiskAcceptanceInput(StrictModel):
    reason: str = Field(..., min_length=20, max_length=2000)
    expires_at: datetime


def _policy(row: RemediationPolicy | None, project: str = "") -> dict:
    values = DEFAULT_POLICY if row is None else {name: int(getattr(row, name)) for name in DEFAULT_POLICY}
    return {"project": project if row is None else row.project, **values,
            "updated_at": row.updated_at.isoformat() + "Z" if row else None}


@router.get("/remediation/policies")
def list_policies(request: Request):
    identity = principal(request)
    with SessionLocal() as db:
        rows = db.scalars(select(RemediationPolicy).order_by(RemediationPolicy.project)).all()
        visible = [row for row in rows if row.project == "" or identity.projects is None or row.project in identity.projects]
        if not any(row.project == "" for row in visible):
            return {"policies": [_policy(None)]}
        return {"policies": [_policy(row) for row in visible]}


@router.put("/remediation/policies")
def put_policy(payload: PolicyInput, request: Request):
    require_admin(request)
    now = _utcnow()
    with SessionLocal.begin() as db:
        row = db.get(RemediationPolicy, payload.project)
        created = row is None
        if row is None:
            row = RemediationPolicy(project=payload.project, created_at=now)
            db.add(row)
        for name in DEFAULT_POLICY:
            setattr(row, name, getattr(payload, name))
        row.updated_at = now
        db.flush()
        affected = refresh_project(db, payload.project if payload.project else None)
        audit_event(db, request, "remediation_policy.create" if created else "remediation_policy.update",
                    "remediation_policy", payload.project or "default",
                    {"affected_findings": affected, **{name: getattr(payload, name) for name in DEFAULT_POLICY}})
        return {"policy": _policy(row), "affected_findings": affected}


@router.get("/intelligence/status")
def intelligence_status(request: Request):
    principal(request)
    now = _utcnow()
    with SessionLocal.begin() as db:
        ensure_sync_states(db)
        db.flush()
        rows = db.scalars(select(IntelligenceSyncState).order_by(IntelligenceSyncState.source)).all()
        return {"sources": [{
            "source": row.source,
            "enabled": row.enabled,
            "interval_hours": row.interval_hours,
            "status": row.status,
            "record_count": row.record_count,
            "last_synced_at": row.last_synced_at.isoformat() + "Z" if row.last_synced_at else None,
            "next_sync_at": row.next_sync_at.isoformat() + "Z",
            "stale": row.last_synced_at is None or row.last_synced_at < now - timedelta(hours=row.interval_hours * 2),
            "last_error": row.last_error,
        } for row in rows]}


@router.put("/intelligence/status/{source}")
def update_intelligence_source(source: Literal["cisa_kev", "first_epss"], payload: SourceSettings, request: Request):
    require_admin(request)
    now = _utcnow()
    with SessionLocal.begin() as db:
        ensure_sync_states(db)
        row = db.get(IntelligenceSyncState, source)
        row.enabled = payload.enabled
        row.interval_hours = payload.interval_hours
        if payload.enabled and row.status in {"idle", "failed", "succeeded"}:
            row.status, row.next_sync_at = "queued", now
            row.last_error = None
        elif not payload.enabled and row.status in {"queued", "syncing"}:
            row.status = "idle"
            row.claim_token = row.claimed_at = None
        row.updated_at = now
        audit_event(db, request, "intelligence.settings", "intelligence_source", source,
                    {"enabled": payload.enabled, "interval_hours": payload.interval_hours})
    return {"ok": True}


@router.post("/intelligence/sync", status_code=202)
def trigger_intelligence_sync(payload: SyncRequest, request: Request):
    require_admin(request)
    sources = list(dict.fromkeys(payload.sources))
    queue_sources(sources)
    with SessionLocal.begin() as db:
        audit_event(db, request, "intelligence.sync_requested", "intelligence_source",
                    details={"sources": sources})
    return {"queued": sources}


@router.post("/findings/{finding_id}/risk-acceptance")
def accept_finding_risk(finding_id: str, payload: RiskAcceptanceInput, request: Request):
    actor = require_admin(request)
    require_user(request)
    now = _utcnow()
    expires_at = payload.expires_at
    if expires_at.tzinfo is not None:
        expires_at = expires_at.astimezone(UTC).replace(tzinfo=None)
    if expires_at <= now or expires_at > now + timedelta(days=365):
        raise HTTPException(422, "Risk acceptance must expire within the next 365 days")
    reason = payload.reason.strip()
    if len(reason) < 20:
        raise HTTPException(422, "Risk acceptance reason must contain at least 20 non-space characters")
    with SessionLocal.begin() as db:
        finding = db.scalar(select(Finding).where(
            Finding.id == finding_id, *project_filters(request, Finding.project)).with_for_update())
        if finding is None:
            raise HTTPException(404, "Finding not found")
        finding.risk_accepted_at = now
        finding.risk_accepted_until = expires_at
        finding.risk_accepted_by = actor.username
        finding.risk_acceptance_reason = reason
        db.add(Comment(finding_id=finding.id, author=actor.username, action_type="risk_acceptance",
                       content=f"Risk accepted until {expires_at.date().isoformat()}: {reason}", created_at=now))
        audit_event(db, request, "finding.risk_accept", "finding", finding.id,
                    {"expires_at": expires_at.isoformat() + "Z", "reason": reason})
    return {"ok": True, "expires_at": expires_at.isoformat() + "Z"}


@router.delete("/findings/{finding_id}/risk-acceptance", status_code=204)
def revoke_finding_risk_acceptance(finding_id: str, request: Request):
    actor = require_admin(request)
    require_user(request)
    with SessionLocal.begin() as db:
        finding = db.scalar(select(Finding).where(
            Finding.id == finding_id, *project_filters(request, Finding.project)).with_for_update())
        if finding is None:
            raise HTTPException(404, "Finding not found")
        if finding.risk_accepted_at is None:
            raise HTTPException(409, "Finding has no risk acceptance to revoke")
        finding.risk_accepted_at = finding.risk_accepted_until = None
        finding.risk_accepted_by = finding.risk_acceptance_reason = None
        db.add(Comment(finding_id=finding.id, author=actor.username, action_type="risk_acceptance_revoked",
                       content="Risk acceptance revoked", created_at=_utcnow()))
        audit_event(db, request, "finding.risk_acceptance_revoke", "finding", finding.id)
    return Response(status_code=204)
