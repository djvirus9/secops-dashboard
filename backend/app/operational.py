"""Operational ownership, security coverage, audit review, and personal queues."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import case, func, select, true
from sqlalchemy.exc import IntegrityError

from .access import audit_event, principal, project_filters, require_admin, require_project, require_user
from .db import SessionLocal
from .github_sync.models import GitHubConnection, GitHubSyncRun
from .models import (
    AuditEvent,
    CoverageExpectation,
    Finding,
    ImportRun,
    ProjectProfile,
    Team,
)

router = APIRouter()

ACTIVE_FINDING_STATUSES = ("open", "investigating", "verification_pending")


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("*", mode="after")
    @classmethod
    def safe_text(cls, value):
        if isinstance(value, str):
            if "\x00" in value:
                raise ValueError("NUL characters are not allowed")
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise ValueError("Text must be valid UTF-8") from exc
        return value


class TeamCreate(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    contact: str = Field("", max_length=255)


class TeamPatch(StrictModel):
    contact: str | None = Field(None, max_length=255)
    active: bool | None = None

    @model_validator(mode="after")
    def has_change(self):
        if not self.model_fields_set:
            raise ValueError("Provide a team field to update")
        return self


class ProjectCreate(StrictModel):
    name: str = Field(min_length=1, max_length=255)
    display_name: str = Field("", max_length=255)
    team_id: UUID | None = None
    business_unit: str = Field("", max_length=255)
    tier: Literal["critical", "high", "medium", "low"] = "medium"
    repository_url: str = Field("", max_length=500)

    @field_validator("name")
    @classmethod
    def bounded_project_name(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 512:
            raise ValueError("Project keys must be at most 512 UTF-8 bytes")
        return value

    @field_validator("repository_url")
    @classmethod
    def safe_repository_url(cls, value: str) -> str:
        if not value:
            return value
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Repository URL must be an HTTPS URL without embedded credentials")
        return value


class ProjectPatch(StrictModel):
    display_name: str | None = Field(None, max_length=255)
    team_id: UUID | None = None
    business_unit: str | None = Field(None, max_length=255)
    tier: Literal["critical", "high", "medium", "low"] | None = None
    repository_url: str | None = Field(None, max_length=500)
    active: bool | None = None

    @field_validator("repository_url")
    @classmethod
    def safe_repository_url(cls, value: str | None) -> str | None:
        if value in (None, ""):
            return value
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Repository URL must be an HTTPS URL without embedded credentials")
        return value

    @model_validator(mode="after")
    def has_change(self):
        if not self.model_fields_set:
            raise ValueError("Provide a project field to update")
        return self


def _team(row: Team) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "contact": row.contact,
        "active": row.active,
        "created_at": row.created_at.isoformat() + "Z",
        "updated_at": row.updated_at.isoformat() + "Z",
    }


def _project(row: ProjectProfile, team: Team | None) -> dict:
    return {
        "name": row.name,
        "display_name": row.display_name,
        "team_id": row.team_id,
        "team_name": team.name if team else None,
        "business_unit": row.business_unit,
        "tier": row.tier,
        "repository_url": row.repository_url,
        "active": row.active,
        "created_at": row.created_at.isoformat() + "Z",
        "updated_at": row.updated_at.isoformat() + "Z",
    }


@router.get("/catalog")
def catalog(request: Request):
    identity = principal(request)
    with SessionLocal() as db:
        projects = db.scalars(select(ProjectProfile).where(
            *project_filters(request, ProjectProfile.name),
        ).order_by(ProjectProfile.name)).all()
        team_ids = {row.team_id for row in projects if row.team_id}
        teams = db.scalars(select(Team).where(
            Team.id.in_(team_ids) if identity.projects is not None else true(),
        ).order_by(Team.name, Team.id)).all()
        team_by_id = {row.id: row for row in teams}
        discovered = set(db.scalars(select(Finding.project).where(
            *project_filters(request, Finding.project),
        ).distinct()))
        discovered.update(db.scalars(select(ImportRun.project).where(
            *project_filters(request, ImportRun.project),
        ).distinct()))
        discovered.update(db.scalars(select(CoverageExpectation.project).where(
            *project_filters(request, CoverageExpectation.project),
        ).distinct()))
        managed = {row.name for row in projects}
        return {
            "teams": [_team(row) for row in teams],
            "projects": [_project(row, team_by_id.get(row.team_id)) for row in projects],
            "unmanaged_projects": sorted(name for name in discovered - managed if name),
        }


@router.post("/catalog/teams", status_code=201)
def create_team(payload: TeamCreate, request: Request):
    require_admin(request)
    with SessionLocal.begin() as db:
        if db.scalar(select(Team.id).where(func.lower(Team.name) == payload.name.lower())):
            raise HTTPException(409, "A team with this name already exists")
        now = utcnow()
        row = Team(name=payload.name, contact=payload.contact, created_at=now, updated_at=now)
        db.add(row)
        db.flush()
        audit_event(db, request, "team.create", "team", row.id, {"name": row.name})
        return {"team": _team(row)}


@router.patch("/catalog/teams/{team_id}")
def patch_team(team_id: UUID, payload: TeamPatch, request: Request):
    require_admin(request)
    with SessionLocal.begin() as db:
        row = db.scalar(select(Team).where(Team.id == str(team_id)).with_for_update())
        if row is None:
            raise HTTPException(404, "Team not found")
        for name in payload.model_fields_set:
            setattr(row, name, getattr(payload, name))
        row.updated_at = utcnow()
        audit_event(db, request, "team.update", "team", row.id,
                    {"fields": sorted(payload.model_fields_set)})
        return {"team": _team(row)}


@router.post("/catalog/projects", status_code=201)
def create_project(payload: ProjectCreate, request: Request):
    require_admin(request)
    with SessionLocal.begin() as db:
        if db.get(ProjectProfile, payload.name):
            raise HTTPException(409, "A project profile with this name already exists")
        team_id = str(payload.team_id) if payload.team_id else None
        if team_id and db.get(Team, team_id) is None:
            raise HTTPException(422, "Selected team does not exist")
        now = utcnow()
        row = ProjectProfile(
            name=payload.name,
            display_name=payload.display_name,
            team_id=team_id,
            business_unit=payload.business_unit,
            tier=payload.tier,
            repository_url=payload.repository_url,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        db.flush()
        audit_event(db, request, "project.create", "project", row.name,
                    {"team_id": row.team_id, "tier": row.tier})
        return {"project": _project(row, db.get(Team, row.team_id) if row.team_id else None)}


@router.patch("/catalog/projects/{project_name:path}")
def patch_project(project_name: str, payload: ProjectPatch, request: Request):
    require_admin(request)
    with SessionLocal.begin() as db:
        row = db.scalar(select(ProjectProfile).where(ProjectProfile.name == project_name).with_for_update())
        if row is None:
            raise HTTPException(404, "Project profile not found")
        if "team_id" in payload.model_fields_set:
            team_id = str(payload.team_id) if payload.team_id else None
            if team_id and db.get(Team, team_id) is None:
                raise HTTPException(422, "Selected team does not exist")
            row.team_id = team_id
        for name in payload.model_fields_set - {"team_id"}:
            setattr(row, name, getattr(payload, name))
        row.updated_at = utcnow()
        audit_event(db, request, "project.update", "project", row.name,
                    {"fields": sorted(payload.model_fields_set)})
        return {"project": _project(row, db.get(Team, row.team_id) if row.team_id else None)}


class CoverageCreate(StrictModel):
    project: str = Field(min_length=1, max_length=255)
    source_type: Literal["scanner", "github"]
    source: str = Field(min_length=1, max_length=200)
    interval_hours: int = Field(24, ge=1, le=2160, strict=True)
    required: bool = True

    @field_validator("project")
    @classmethod
    def bounded_project_name(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 512:
            raise ValueError("Project keys must be at most 512 UTF-8 bytes")
        return value

    @model_validator(mode="after")
    def normalize_source(self):
        if self.source_type == "github":
            self.source = self.source.lower()
        return self


class CoveragePatch(StrictModel):
    interval_hours: int | None = Field(None, ge=1, le=2160, strict=True)
    required: bool | None = None
    enabled: bool | None = None

    @model_validator(mode="after")
    def has_change(self):
        if not self.model_fields_set:
            raise ValueError("Provide a coverage field to update")
        return self


def _latest_import(db, expectation: CoverageExpectation):
    base = [ImportRun.project == expectation.project, ImportRun.parser == expectation.source]
    latest = db.scalar(select(ImportRun).where(*base)
                       .order_by(ImportRun.created_at.desc(), ImportRun.id.desc()).limit(1))
    success = db.scalar(select(ImportRun).where(*base, ImportRun.status == "completed")
                        .order_by(ImportRun.completed_at.desc(), ImportRun.id.desc()).limit(1))
    clean = db.scalar(select(ImportRun).where(*base, ImportRun.status == "completed", ImportRun.imported == 0)
                      .order_by(ImportRun.completed_at.desc(), ImportRun.id.desc()).limit(1))
    return latest, success, clean


def _latest_github(db, expectation: CoverageExpectation):
    connection = db.scalar(select(GitHubConnection).where(
        GitHubConnection.project == expectation.project,
        GitHubConnection.repository == expectation.source,
    ))
    if connection is None:
        return None, None, None
    latest = db.scalar(select(GitHubSyncRun).where(GitHubSyncRun.connection_id == connection.id)
                       .order_by(GitHubSyncRun.started_at.desc(), GitHubSyncRun.id.desc()).limit(1))
    success = db.scalar(select(GitHubSyncRun).where(
        GitHubSyncRun.connection_id == connection.id, GitHubSyncRun.status == "succeeded",
    ).order_by(GitHubSyncRun.completed_at.desc(), GitHubSyncRun.id.desc()).limit(1))
    # GitHub can omit alerts because visibility or retention changed. A zero-row
    # snapshot is therefore not represented as clean-scan evidence.
    return latest, success, None


def _coverage_row(db, row: CoverageExpectation, now: datetime, team_name: str | None) -> dict:
    latest, success, clean = (
        _latest_import(db, row) if row.source_type == "scanner" else _latest_github(db, row)
    )
    latest_started = getattr(latest, "created_at", None) or getattr(latest, "started_at", None)
    latest_completed = getattr(latest, "completed_at", None)
    latest_status = getattr(latest, "status", None)
    success_at = getattr(success, "completed_at", None)
    clean_at = getattr(clean, "completed_at", None)
    next_due = success_at + timedelta(hours=row.interval_hours) if success_at else None
    if not row.enabled:
        health = "disabled"
    elif latest_status in {"failed", "interrupted"} and (not success_at or (latest_started and latest_started > success_at)):
        health = "failing"
    elif success_at is None:
        health = "missing"
    elif next_due and next_due < now:
        health = "stale"
    else:
        health = "healthy"
    return {
        "id": row.id,
        "project": row.project,
        "team": team_name,
        "source_type": row.source_type,
        "source": row.source,
        "interval_hours": row.interval_hours,
        "required": row.required,
        "enabled": row.enabled,
        "health": health,
        "last_status": latest_status,
        "last_started_at": latest_started.isoformat() + "Z" if latest_started else None,
        "last_completed_at": latest_completed.isoformat() + "Z" if latest_completed else None,
        "last_successful_at": success_at.isoformat() + "Z" if success_at else None,
        "last_clean_at": clean_at.isoformat() + "Z" if clean_at else None,
        "last_findings": getattr(latest, "imported", None),
        "next_due_at": next_due.isoformat() + "Z" if next_due else None,
    }


@router.get("/coverage")
def coverage(request: Request):
    with SessionLocal() as db:
        rows = db.scalars(select(CoverageExpectation).where(
            *project_filters(request, CoverageExpectation.project),
        ).order_by(CoverageExpectation.project, CoverageExpectation.source_type, CoverageExpectation.source)).all()
        project_names = {row.project for row in rows}
        project_rows = (
            db.scalars(select(ProjectProfile).where(ProjectProfile.name.in_(project_names))).all()
            if project_names else []
        )
        team_ids = {row.team_id for row in project_rows if row.team_id}
        team_names = {row.id: row.name for row in db.scalars(select(Team).where(Team.id.in_(team_ids))).all()} if team_ids else {}
        project_teams = {row.name: team_names.get(row.team_id) for row in project_rows}
        results = [_coverage_row(db, row, utcnow(), project_teams.get(row.project)) for row in rows]
        counts = {name: sum(result["health"] == name for result in results)
                  for name in ("healthy", "stale", "failing", "missing", "disabled")}
        required_attention = sum(
            result["required"] and result["enabled"] and result["health"] != "healthy"
            for result in results
        )
        return {"count": len(results), "required_attention": required_attention,
                "health": counts, "results": results, "generated_at": utcnow().isoformat() + "Z"}


@router.post("/coverage", status_code=201)
def create_coverage(payload: CoverageCreate, request: Request):
    require_admin(request)
    require_project(request, payload.project)
    now = utcnow()
    try:
        with SessionLocal.begin() as db:
            row = CoverageExpectation(
                project=payload.project,
                source_type=payload.source_type,
                source=payload.source,
                interval_hours=payload.interval_hours,
                required=payload.required,
                created_at=now,
                updated_at=now,
            )
            db.add(row)
            db.flush()
            audit_event(db, request, "coverage.create", "coverage_expectation", row.id,
                        {"project": row.project, "source_type": row.source_type, "source": row.source})
            return {"expectation": _coverage_row(db, row, now, None)}
    except IntegrityError as exc:
        raise HTTPException(409, "This project and source already have a coverage expectation") from exc


@router.patch("/coverage/{expectation_id}")
def patch_coverage(expectation_id: UUID, payload: CoveragePatch, request: Request):
    require_admin(request)
    with SessionLocal.begin() as db:
        row = db.scalar(select(CoverageExpectation).where(
            CoverageExpectation.id == str(expectation_id),
        ).with_for_update())
        if row is None:
            raise HTTPException(404, "Coverage expectation not found")
        require_project(request, row.project)
        for name in payload.model_fields_set:
            setattr(row, name, getattr(payload, name))
        row.updated_at = utcnow()
        audit_event(db, request, "coverage.update", "coverage_expectation", row.id,
                    {"fields": sorted(payload.model_fields_set)})
        return {"expectation": _coverage_row(db, row, utcnow(), None)}


def _json_details(value: str) -> dict:
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


@router.get("/audit-events")
def audit_events(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    actor: str = "",
    action: str = "",
    object_type: str = "",
):
    require_admin(request)
    limit, offset = max(1, min(limit, 200)), max(0, offset)
    filters = []
    for column, value in (
        (AuditEvent.actor, actor), (AuditEvent.action, action), (AuditEvent.object_type, object_type),
    ):
        if value.strip():
            filters.append(column.icontains(value.strip()[:100], autoescape=True))
    with SessionLocal() as db:
        rows = db.scalars(select(AuditEvent).where(*filters)
                          .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
                          .offset(offset).limit(limit)).all()
        count = db.scalar(select(func.count()).select_from(AuditEvent).where(*filters)) or 0
        return {"count": int(count), "page_count": len(rows), "offset": offset, "results": [{
            "id": row.id,
            "actor": row.actor,
            "action": row.action,
            "object_type": row.object_type,
            "object_id": row.object_id,
            "details": _json_details(row.details_json),
            "created_at": row.created_at.isoformat() + "Z",
        } for row in rows]}


@router.get("/my-queue")
def my_queue(request: Request, limit: int = 50, offset: int = 0):
    identity = require_user(request)
    limit, offset = max(1, min(limit, 200)), max(0, offset)
    filters = [
        *project_filters(request, Finding.project),
        Finding.assignee == identity.username,
        Finding.status.in_(ACTIVE_FINDING_STATUSES),
    ]
    with SessionLocal() as db:
        rows = db.scalars(select(Finding).where(*filters)
                          .order_by(
                              Finding.priority_score.desc(),
                              case((Finding.remediation_due_at.is_(None), 1), else_=0),
                              Finding.remediation_due_at,
                              Finding.id,
                          )
                          .offset(offset).limit(limit)).all()
        count = db.scalar(select(func.count()).select_from(Finding).where(*filters)) or 0
        now = utcnow()
        overdue = db.scalar(select(func.count()).select_from(Finding).where(
            *filters,
            Finding.remediation_due_at < now,
            (Finding.risk_accepted_until.is_(None) | (Finding.risk_accepted_until <= now)),
        )) or 0
        return {
            "count": int(count),
            "overdue": int(overdue),
            "page_count": len(rows),
            "offset": offset,
            "results": [{
                "id": row.id,
                "project": row.project,
                "title": row.title,
                "asset": row.asset,
                "severity": row.severity,
                "status": row.status,
                "priority_score": row.priority_score,
                "remediation_due_at": row.remediation_due_at.isoformat() + "Z" if row.remediation_due_at else None,
                "last_seen": row.last_seen.isoformat() + "Z",
            } for row in rows],
        }
