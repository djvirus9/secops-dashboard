"""One filtering contract for finding lists, saved views, and CSV downloads."""
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import or_

from .models import Finding

Severity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal["open", "investigating", "resolved", "closed"]
FindingSort = Literal["priority_desc", "risk_desc", "last_seen_desc"]
SlaFilter = Literal["overdue", "due_soon", "accepted", "on_track"]


class FindingFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    q: str = Field("", max_length=500)
    severity: Severity | None = None
    status: FindingStatus | None = None
    assignee: str | None = Field(None, max_length=255)
    tool: str | None = Field(None, max_length=100)
    project: str | None = Field(None, max_length=255)
    kev: bool | None = None
    sla: SlaFilter | None = None
    sort: FindingSort = "last_seen_desc"

    @field_validator("severity", "status", "kev", "sla", mode="before")
    @classmethod
    def empty_choice(cls, value):
        return None if value == "" else value

    @field_validator("q", "assignee", "tool", "project")
    @classmethod
    def valid_text(cls, value):
        if value is not None:
            if "\x00" in value:
                raise ValueError("Filter text cannot contain NUL characters")
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise ValueError("Filter text must be valid Unicode") from exc
        return value


def finding_filters(query: FindingFilters) -> list:
    filters = []
    if query.q.strip():
        filters.append(or_(*(column.icontains(query.q.strip(), autoescape=True) for column in
                            (Finding.title, Finding.asset, Finding.cve_id, Finding.component))))
    for column, value in ((Finding.severity, query.severity), (Finding.status, query.status),
                          (Finding.tool, query.tool), (Finding.project, query.project)):
        if value is not None:
            filters.append(column == value)
    if query.assignee is not None:
        filters.append(Finding.assignee.is_(None) if query.assignee == "" else Finding.assignee == query.assignee)
    if query.kev is not None:
        filters.append(Finding.kev.is_(query.kev))
    if query.sla is not None:
        now = datetime.now(UTC).replace(tzinfo=None)
        active = Finding.status.in_(["open", "investigating"])
        accepted = Finding.risk_accepted_until > now
        if query.sla == "accepted":
            filters.extend([active, accepted])
        elif query.sla == "overdue":
            filters.extend([active, Finding.remediation_due_at < now,
                            or_(Finding.risk_accepted_until.is_(None), Finding.risk_accepted_until <= now)])
        elif query.sla == "due_soon":
            filters.extend([active, Finding.remediation_due_at >= now,
                            Finding.remediation_due_at <= now + timedelta(days=7),
                            or_(Finding.risk_accepted_until.is_(None), Finding.risk_accepted_until <= now)])
        else:
            filters.extend([active, Finding.remediation_due_at > now + timedelta(days=7),
                            or_(Finding.risk_accepted_until.is_(None), Finding.risk_accepted_until <= now)])
    return filters


def finding_order(sort: FindingSort) -> list:
    order = [Finding.last_seen.desc(), Finding.id]
    if sort == "priority_desc":
        order.insert(0, Finding.priority_score.desc())
    elif sort == "risk_desc":
        order.insert(0, Finding.risk_score.desc())
    return order
