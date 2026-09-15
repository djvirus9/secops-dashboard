from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from ..models import _utcnow


class JiraIssueLink(Base):
    __tablename__ = "jira_issue_links"

    finding_id: Mapped[str] = mapped_column(String, ForeignKey("findings.id"), primary_key=True)
    issue_key: Mapped[str] = mapped_column(String(80))
    base_url: Mapped[str] = mapped_column(String(255))
    remote_status_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    remote_status: Mapped[str | None] = mapped_column(String(200), nullable=True)
    remote_status_category: Mapped[str | None] = mapped_column(String(20), nullable=True)
    remote_assignee_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    remote_assignee: Mapped[str | None] = mapped_column(String(200), nullable=True)
    remote_updated_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    local_snapshot_json: Mapped[str] = mapped_column(Text, default="{}")
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_sync_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    status: Mapped[str] = mapped_column(String(20), default="idle")
    operation: Mapped[str] = mapped_column(String(20), default="pull")
    pending_json: Mapped[str] = mapped_column(Text, default="{}")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    claim_token: Mapped[str | None] = mapped_column(String, nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class JiraUserMapping(Base):
    __tablename__ = "jira_user_mappings"

    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), primary_key=True)
    jira_account_id: Mapped[str] = mapped_column(String(128), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class JiraSyncControl(Base):
    """One tenant-wide lease and cooldown, shared by all worker replicas."""
    __tablename__ = "jira_sync_control"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    claim_token: Mapped[str | None] = mapped_column(String, nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_request_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
