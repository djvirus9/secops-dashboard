"""Private saved views, atomic triage, and bounded finding exports."""
from __future__ import annotations

import csv
import io
import json
import unicodedata
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from .access import audit_event, principal, project_filters, require_user, require_write
from .db import SessionLocal
from .finding_query import FindingFilters, FindingStatus, finding_filters, finding_order
from .models import Comment, Finding, SavedView, User

router = APIRouter()
MAX_SAVED_VIEWS = 100
MAX_EXPORT_ROWS = 10_000
MAX_EXPORT_BYTES = 16 * 1024 * 1024


def utcnow():
    return datetime.now(UTC).replace(tzinfo=None)


class ViewCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    filters: FindingFilters = Field(default_factory=FindingFilters)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value):
        value = value.strip()
        if not value or any(unicodedata.category(char).startswith("C") for char in value):
            raise ValueError("Name must contain visible text without control characters")
        return value


class ViewUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(None, min_length=1, max_length=100)
    filters: FindingFilters | None = None

    @model_validator(mode="after")
    def validate_update(self):
        if not self.model_fields_set or any(getattr(self, name) is None for name in self.model_fields_set):
            raise ValueError("Provide a name or filters to update")
        if self.name is not None:
            self.name = ViewCreate.valid_name(self.name)
        return self


def serialize_view(view: SavedView):
    return {"id": view.id, "name": view.name, "filters": json.loads(view.filters_json),
            "created_at": view.created_at.isoformat() + "Z", "updated_at": view.updated_at.isoformat() + "Z"}


@router.get("/saved-views")
def list_views(request: Request):
    user = require_user(request)
    with SessionLocal() as db:
        rows = db.scalars(select(SavedView).where(SavedView.user_id == user.id)
                          .order_by(SavedView.name, SavedView.id)).all()
        return {"results": [serialize_view(row) for row in rows]}


@router.post("/saved-views", status_code=201)
def create_view(payload: ViewCreate, request: Request):
    user = require_user(request)
    try:
        with SessionLocal.begin() as db:
            # An actual write locks concurrent creates on SQLite as well as
            # PostgreSQL; SQLite ignores SELECT FOR UPDATE.
            db.execute(update(User).where(User.id == user.id).values(updated_at=User.updated_at))
            count = db.scalar(select(func.count()).select_from(SavedView).where(SavedView.user_id == user.id)) or 0
            if count >= MAX_SAVED_VIEWS:
                raise HTTPException(422, "Saved view limit reached; delete an unused view first")
            view = SavedView(user_id=user.id, name=payload.name,
                             filters_json=payload.filters.model_dump_json(exclude_none=True))
            db.add(view)
            db.flush()
            audit_event(db, request, "saved_view.create", "saved_view", view.id)
            result = serialize_view(view)
        return result
    except IntegrityError as exc:
        raise HTTPException(409, "You already have a saved view with this name") from exc


@router.patch("/saved-views/{view_id}")
def update_view(view_id: UUID, payload: ViewUpdate, request: Request):
    user = require_user(request)
    try:
        with SessionLocal.begin() as db:
            view = db.scalar(select(SavedView).where(SavedView.id == str(view_id), SavedView.user_id == user.id)
                             .with_for_update())
            if view is None:
                raise HTTPException(404, "Saved view not found")
            if payload.name is not None:
                view.name = payload.name
            if payload.filters is not None:
                view.filters_json = payload.filters.model_dump_json(exclude_none=True)
            view.updated_at = utcnow()
            audit_event(db, request, "saved_view.update", "saved_view", view.id)
            db.flush()
            result = serialize_view(view)
        return result
    except IntegrityError as exc:
        raise HTTPException(409, "You already have a saved view with this name") from exc


@router.delete("/saved-views/{view_id}", status_code=204)
def delete_view(view_id: UUID, request: Request):
    user = require_user(request)
    with SessionLocal.begin() as db:
        view = db.scalar(select(SavedView).where(SavedView.id == str(view_id), SavedView.user_id == user.id)
                         .with_for_update())
        if view is None:
            raise HTTPException(404, "Saved view not found")
        audit_event(db, request, "saved_view.delete", "saved_view", view.id)
        db.delete(view)
    return Response(status_code=204)


class BulkUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ids: list[UUID] = Field(min_length=1, max_length=200)
    status: FindingStatus | None = None
    assignee: str | None = Field(None, max_length=255)

    @model_validator(mode="after")
    def validate_changes(self):
        if len(set(self.ids)) != len(self.ids):
            raise ValueError("Select each finding only once")
        if not ({"status", "assignee"} & self.model_fields_set):
            raise ValueError("Provide a status or assignee to update")
        if "status" in self.model_fields_set and self.status is None:
            raise ValueError("Status cannot be null")
        if self.assignee is not None:
            FindingFilters.valid_text(self.assignee)
        return self


@router.post("/findings/bulk")
def bulk_update(payload: BulkUpdate, request: Request):
    actor = require_write(request)
    if actor.kind == "scanner":
        raise HTTPException(403, "Scanner credentials cannot triage findings")
    ids = sorted(str(value) for value in payload.ids)
    with SessionLocal.begin() as db:
        rows = db.scalars(select(Finding).where(Finding.id.in_(ids), *project_filters(request, Finding.project))
                          .order_by(Finding.id).with_for_update()).all()
        # Check the complete selection before modifying anything or revealing IDs.
        if len(rows) != len(ids):
            raise HTTPException(404, "One or more selected findings are unavailable; refresh your selection")
        changed = 0
        now = utcnow()
        for finding in rows:
            changes = []
            if payload.status is not None and payload.status != finding.status:
                changes.append(f"Status changed from '{finding.status}' to '{payload.status}'")
                finding.status = payload.status
            if "assignee" in payload.model_fields_set:
                assignee = payload.assignee or None
                if assignee != finding.assignee:
                    changes.append(f"Assignee changed from '{finding.assignee or 'unassigned'}' to '{assignee or 'unassigned'}'")
                    finding.assignee = assignee
            if changes:
                db.add(Comment(finding_id=finding.id, author=actor.username, content="; ".join(changes),
                               action_type="update", created_at=now))
                changed += 1
        audit_event(db, request, "findings.bulk_update", "finding", details={"ids": ids, "updated": changed,
                    "fields": sorted(payload.model_fields_set - {"ids"})})
    return {"ok": True, "updated": changed}


EXPORT_COLUMNS = ("id", "project", "tool", "title", "severity", "status", "assignee", "risk_score",
                  "asset", "component", "component_version", "cve_id", "cvss_score", "file_path",
                  "line_number", "first_seen", "last_seen", "occurrences")


def csv_cell(value):
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat() + "Z"
    text = str(value)
    # Ordinary visible text survives spreadsheet save/re-open cycles, unlike
    # relying only on quotes/apostrophes that some spreadsheet tools remove.
    inspected = text.lstrip()
    if (inspected.startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠"))
            or (text and ord(text[0]) < 32)
            or (inspected and unicodedata.category(inspected[0]).startswith("C"))):
        return "[text] " + text
    return text


@router.get("/findings/export.csv")
def export_findings(request: Request, query: Annotated[FindingFilters, Query()]):
    actor = principal(request)
    if actor.kind == "scanner":
        raise HTTPException(403, "Scanner credentials cannot export findings")
    output = io.BytesIO(b"\xef\xbb\xbf")
    output.seek(0, io.SEEK_END)
    line = io.StringIO(newline="")
    writer = csv.writer(line, quoting=csv.QUOTE_ALL, lineterminator="\r\n")

    def write_row(values):
        line.seek(0)
        line.truncate(0)
        writer.writerow(values)
        encoded = line.getvalue().encode("utf-8")
        if output.tell() + len(encoded) > MAX_EXPORT_BYTES:
            raise HTTPException(422, "Export exceeds 16 MiB; refine the filters and try again")
        output.write(encoded)

    write_row(EXPORT_COLUMNS)
    count = 0
    with SessionLocal.begin() as db:
        # Select summary columns only: never load raw evidence or full descriptions.
        statement = select(*(getattr(Finding, name) for name in EXPORT_COLUMNS)).where(
            *project_filters(request, Finding.project), *finding_filters(query),
        ).order_by(*finding_order(query.sort)).limit(MAX_EXPORT_ROWS + 1)
        for row in db.execute(statement.execution_options(yield_per=200)):
            count += 1
            if count > MAX_EXPORT_ROWS:
                raise HTTPException(422, "Export exceeds 10000 findings; refine the filters and try again")
            write_row(csv_cell(value) for value in row)
        audit_event(db, request, "findings.export", "finding", details={"count": count})
    return Response(output.getvalue(), media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": 'attachment; filename="secops-findings.csv"',
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
    })
