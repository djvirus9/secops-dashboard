"""Real ownership, exact-grant assignment, and opt-in new-finding routing.

Team membership is organizational metadata, never a project access grant.
Legacy assignee text is retained but invalid owners remain actionable in queues.
"""
from __future__ import annotations

import json
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import and_, case, cast, column, func, literal, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import object_session

from .access import audit_event, principal, project_filters, require_admin, require_project, require_user
from .accounts import _lock_accounts, user_projects
from .db import SessionLocal
from .finding_query import ACTIVE_FINDING_STATUSES
from .models import AuditEvent, Comment, Finding, OwnershipRule, ProjectProfile, Team, TeamMembership, User, _utcnow

router = APIRouter()
MAX_TEAM_MEMBERS = 500


def assignee_is_eligible(user: User | None, project: str) -> bool:
    if user is None or not user.active or user.role not in {"admin", "analyst"}:
        return False
    projects = user_projects(user)
    return projects is None or project in projects


def validate_assignee(db, username: str | None, projects) -> str | None:
    """Validate the entire selection before any status/assignment mutation."""
    username = username.strip() if username else None
    if not username:
        return None
    user = db.scalar(select(User).where(User.username == username))
    if not all(assignee_is_eligible(user, project) for project in set(projects)):
        raise HTTPException(422, "Assignee must be an active administrator or analyst with access to every selected project")
    return username


def eligible_project_clause(db, project):
    """SQL equivalent of user_projects, including corrupt-grant fail-closed behavior.

    Native JSON membership preserves exact project names, including quotes,
    slashes, percent signs, Unicode and empty legacy project keys. PostgreSQL
    deployments use version 16 (the version pinned in compose.services.yml).
    """
    if db.get_bind().dialect.name == "postgresql":
        valid = func.pg_input_is_valid(User.projects_json, "jsonb")
        parsed = cast(case((valid, User.projects_json), else_="[]"), JSONB)
        array = case((func.jsonb_typeof(parsed) == "array", parsed), else_=cast(literal("[]"), JSONB))
        items = func.jsonb_array_elements(array).table_valued(column("value", JSONB)).alias("grants")
        invalid = select(1).select_from(items).where(func.jsonb_typeof(items.c.value) != "string").correlate(User).exists()
        member = array.op("@>")(func.jsonb_build_array(project))
    else:
        parsed = case((func.json_valid(User.projects_json) == 1, User.projects_json), else_="[]")
        array = case((func.json_type(parsed) == "array", parsed), else_="[]")
        items = func.json_each(array).table_valued("value", "type").alias("grants")
        invalid = select(1).select_from(items).where(items.c.type != "text").correlate(User).exists()
        member = select(1).select_from(items).where(items.c.value == project).correlate(User, Finding).exists()
    return and_(User.active.is_(True), User.role.in_(("admin", "analyst")), or_(
        User.role == "admin", User.projects_json.is_(None), and_(~invalid, member),
    ))


def valid_owner_clause(db):
    return select(1).select_from(User).where(
        User.username == Finding.assignee, eligible_project_clause(db, Finding.project),
    ).correlate(Finding).exists()


def finding_ownership(finding: Finding) -> dict:
    db = object_session(finding)
    # A response commonly contains many findings sharing the same owner/team.
    # Keep lookup work proportional to distinct identities, not result count.
    cache = db.info.setdefault("ownership_serialization", {}) if db else {}
    profiles = cache.setdefault("projects", {})
    teams = cache.setdefault("teams", {})
    owners = cache.setdefault("users", {})
    if db and finding.project not in profiles:
        profiles[finding.project] = db.get(ProjectProfile, finding.project)
    profile = profiles.get(finding.project)
    if db and profile and profile.team_id and profile.team_id not in teams:
        teams[profile.team_id] = db.get(Team, profile.team_id)
    team = teams.get(profile.team_id) if profile else None
    if db and finding.assignee and finding.assignee not in owners:
        owners[finding.assignee] = db.scalar(select(User).where(User.username == finding.assignee))
    owner = owners.get(finding.assignee)
    return {
        "status": "assigned" if assignee_is_eligible(owner, finding.project) else (
            "invalid_assignee" if finding.assignee else "unassigned"),
        "team_id": team.id if team else None,
        "team_name": team.name if team else None,
    }


def _rule_details(db, profile: ProjectProfile, rule: OwnershipRule | None) -> dict:
    team = db.get(Team, profile.team_id) if profile.team_id else None
    warning = None
    if not profile.active:
        warning = "Project is inactive"
    elif team is None or not team.active:
        warning = "Choose an active owning team in the catalog"
    elif rule and rule.default_assignee:
        user = db.scalar(select(User).where(User.username == rule.default_assignee))
        if not assignee_is_eligible(user, profile.name) or not db.get(TeamMembership, (team.id, user.id)):
            warning = "Default assignee is no longer an eligible member of the owning team"
    return {"project": profile.name, "team_id": profile.team_id, "team_name": team.name if team else None,
            "enabled": bool(rule and rule.enabled), "default_assignee": rule.default_assignee if rule else None,
            "ready": warning is None, "warning": warning}


def route_new_finding(db, finding: Finding, *, actor="ownership-router") -> None:
    """Called only after a new insert; repeat scans never reassign existing work."""
    if finding.assignee or finding.status not in ACTIVE_FINDING_STATUSES:
        return
    rule = db.get(OwnershipRule, finding.project)
    if rule is None or not rule.enabled:
        return
    profile = db.get(ProjectProfile, finding.project)
    if profile is None:
        return
    details = _rule_details(db, profile, rule)
    now = _utcnow()
    if not details["ready"]:
        content = f"Automatic routing needs an owner: {details['warning']}"
        action = "ownership.routing_skipped"
    else:
        finding.assignee = rule.default_assignee
        content = f"Routed to owning team '{details['team_name']}'"
        if finding.assignee:
            content += f" and assigned to '{finding.assignee}'"
        else:
            content += "; a team member must claim this finding"
        action = "ownership.routed"
    db.add(Comment(finding_id=finding.id, author=actor, action_type="ownership", content=content, created_at=now))
    db.add(AuditEvent(actor=actor, action=action, object_type="finding", object_id=finding.id,
                      details_json=json.dumps({"project": finding.project, "team_id": details["team_id"],
                                               "assignee": finding.assignee, "warning": details["warning"]}), created_at=now))


@router.get("/ownership/assignees")
def assignees(request: Request, project: str = Query("", max_length=255),
              limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0)):
    require_project(request, project)
    with SessionLocal() as db:
        filters = [eligible_project_clause(db, literal(project))]
        total = db.scalar(select(func.count()).select_from(User).where(*filters)) or 0
        rows = db.scalars(select(User).where(*filters).order_by(User.username, User.id).limit(limit).offset(offset)).all()
        return {"count": total, "offset": offset, "results": [
            {"id": user.id, "username": user.username, "role": user.role} for user in rows]}


@router.get("/ownership/teams/{team_id}/members")
def members(team_id: UUID, request: Request):
    require_admin(request)
    with SessionLocal() as db:
        if db.get(Team, str(team_id)) is None:
            raise HTTPException(404, "Team not found")
        rows = db.scalars(select(User).join(TeamMembership, TeamMembership.user_id == User.id)
                          .where(TeamMembership.team_id == str(team_id)).order_by(User.username).limit(MAX_TEAM_MEMBERS)).all()
        return {"results": [{"id": row.id, "username": row.username, "role": row.role, "active": row.active} for row in rows]}


@router.put("/ownership/teams/{team_id}/members/{user_id}")
def add_member(team_id: UUID, user_id: UUID, request: Request):
    require_admin(request)
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        team, user = db.get(Team, str(team_id)), db.get(User, str(user_id))
        if team is None or user is None:
            raise HTTPException(404, "Team or user not found")
        if not team.active or not user.active or user.role not in {"admin", "analyst"}:
            raise HTTPException(422, "Membership requires an active team and an active administrator or analyst")
        if db.get(TeamMembership, (team.id, user.id)) is None:
            count = db.scalar(select(func.count()).select_from(TeamMembership).where(TeamMembership.team_id == team.id)) or 0
            if count >= MAX_TEAM_MEMBERS:
                raise HTTPException(422, "Team membership limit reached")
            db.add(TeamMembership(team_id=team.id, user_id=user.id))
            audit_event(db, request, "team.member_added", "team", team.id, {"user_id": user.id})
        return {"ok": True}


@router.delete("/ownership/teams/{team_id}/members/{user_id}", status_code=204)
def remove_member(team_id: UUID, user_id: UUID, request: Request):
    require_admin(request)
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        row = db.get(TeamMembership, (str(team_id), str(user_id)))
        if row is None:
            raise HTTPException(404, "Team membership not found")
        db.delete(row)
        audit_event(db, request, "team.member_removed", "team", str(team_id), {"user_id": str(user_id)})
    return Response(status_code=204)


@router.get("/ownership/my-teams")
def my_teams(request: Request):
    user = require_user(request)
    with SessionLocal() as db:
        visible = select(ProjectProfile.team_id).where(*project_filters(request, ProjectProfile.name))
        rows = db.scalars(select(Team).join(TeamMembership, TeamMembership.team_id == Team.id).where(
            TeamMembership.user_id == user.id, Team.id.in_(visible),
        ).order_by(Team.name).limit(500)).all()
        return {"results": [{"id": row.id, "name": row.name, "active": row.active} for row in rows]}


@router.get("/ownership/rules")
def rules(request: Request, project: str | None = Query(None, max_length=255),
          limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0)):
    filters = project_filters(request, ProjectProfile.name)
    if project is not None:
        require_project(request, project)
        filters.append(ProjectProfile.name == project)
    with SessionLocal() as db:
        total = db.scalar(select(func.count()).select_from(ProjectProfile).where(*filters)) or 0
        rows = db.scalars(select(ProjectProfile).where(*filters).order_by(ProjectProfile.name).limit(limit).offset(offset)).all()
        return {"count": total, "offset": offset,
                "results": [_rule_details(db, row, db.get(OwnershipRule, row.name)) for row in rows]}


class RulePut(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    enabled: bool
    default_assignee: str | None = Field(None, max_length=100)

    @field_validator("default_assignee")
    @classmethod
    def empty_is_none(cls, value):
        return value or None


@router.put("/ownership/rules")
def put_rule(payload: RulePut, request: Request, project: str = Query(..., max_length=255)):
    require_admin(request)
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        profile = db.get(ProjectProfile, project)
        if profile is None:
            raise HTTPException(404, "Project profile not found")
        default = validate_assignee(db, payload.default_assignee, [project]) if payload.enabled else payload.default_assignee
        rule = OwnershipRule(project=project, enabled=payload.enabled, default_assignee=default)
        details = _rule_details(db, profile, rule)
        if payload.enabled and not details["ready"]:
            raise HTTPException(422, details["warning"])
        existing = db.get(OwnershipRule, project)
        if existing:
            existing.enabled, existing.default_assignee, existing.updated_at = payload.enabled, default, _utcnow()
        else:
            db.add(rule)
        audit_event(db, request, "ownership.rule_updated", "project", project,
                    {"enabled": payload.enabled, "default_assignee": default, "team_id": profile.team_id})
        return details


@router.get("/ownership/queue")
def queue(request: Request, view: Literal["unassigned", "team"] = "unassigned",
          team_id: UUID | None = None, project: str | None = Query(None, max_length=255),
          limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    from .main import _serialize_finding

    identity = principal(request)
    filters = [*project_filters(request, Finding.project), Finding.status.in_(ACTIVE_FINDING_STATUSES)]
    if project is not None:
        require_project(request, project)
        filters.append(Finding.project == project)
    with SessionLocal() as db:
        if view == "unassigned":
            filters.append(~valid_owner_clause(db))
            if team_id is not None:
                raise HTTPException(422, "Choose the team view to filter by team")
        else:
            if team_id is None:
                user = require_user(request)
                team_ids = select(TeamMembership.team_id).where(TeamMembership.user_id == user.id)
            else:
                if identity.role != "admin":
                    user = require_user(request)
                    if db.get(TeamMembership, (str(team_id), user.id)) is None:
                        raise HTTPException(404, "Team not found")
                team_ids = [str(team_id)]
            filters.append(Finding.project.in_(select(ProjectProfile.name).where(ProjectProfile.team_id.in_(team_ids))))
        total = db.scalar(select(func.count()).select_from(Finding).where(*filters)) or 0
        now = _utcnow()
        overdue = db.scalar(select(func.count()).select_from(Finding).where(
            *filters, Finding.remediation_due_at < now,
            or_(Finding.risk_accepted_until.is_(None), Finding.risk_accepted_until <= now),
        )) or 0
        rows = db.scalars(select(Finding).where(*filters).order_by(
            Finding.priority_score.desc(), Finding.remediation_due_at.asc().nulls_last(), Finding.id,
        ).offset(offset).limit(limit)).all()
        return {"count": total, "overdue": overdue, "offset": offset,
                "results": [_serialize_finding(row) for row in rows]}
