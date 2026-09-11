from __future__ import annotations

from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from ..models import _utcnow, _uuid


class GitHubConnection(Base):
    __tablename__ = "github_connections"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    repository: Mapped[str] = mapped_column(String(200), unique=True)
    project: Mapped[str] = mapped_column(String(255))
    sources_json: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    next_sync_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    claim_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class GitHubSyncRun(Base):
    __tablename__ = "github_sync_runs"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    connection_id: Mapped[str] = mapped_column(String, ForeignKey("github_connections.id"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="syncing")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    imported: Mapped[int] = mapped_column(Integer, default=0)
    new_findings: Mapped[int] = mapped_column(Integer, default=0)
    updated: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)


class GitHubAlert(Base):
    __tablename__ = "github_alerts"
    __table_args__ = (UniqueConstraint("connection_id", "source", "number", name="uq_github_alert_identity"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    connection_id: Mapped[str] = mapped_column(String, ForeignKey("github_connections.id"), index=True)
    source: Mapped[str] = mapped_column(String(20))
    number: Mapped[int] = mapped_column(Integer)
    finding_id: Mapped[str] = mapped_column(String, ForeignKey("findings.id"), unique=True)
    source_state: Mapped[str] = mapped_column(String(20))
    content_hash: Mapped[str] = mapped_column(String(64))
    last_synced_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
