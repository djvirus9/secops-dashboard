from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import String, Integer, Float, DateTime, Text, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _uuid() -> str:
    return str(uuid4())


def _utcnow() -> datetime:
    # Database columns intentionally remain naive UTC for migration
    # compatibility; avoid the deprecated datetime.utcnow().
    return datetime.now(UTC).replace(tzinfo=None)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("project", "key", name="uq_assets_project_key"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project: Mapped[str] = mapped_column(String, default="", index=True)
    key: Mapped[str] = mapped_column(String, index=True)
    name: Mapped[str] = mapped_column(String, default="")
    environment: Mapped[str] = mapped_column(String, default="unknown")
    owner: Mapped[str] = mapped_column(String, default="")
    criticality: Mapped[str] = mapped_column(String, default="medium")
    exposure: Mapped[str] = mapped_column(String, default="internal")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    findings: Mapped[list["Finding"]] = relationship(back_populates="asset_rel")


class Signal(Base):
    __tablename__ = "signals"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    tool: Mapped[str] = mapped_column(String, index=True)
    import_id: Mapped[str | None] = mapped_column(String, ForeignKey("imports.id"), nullable=True, index=True)
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("fingerprint", name="uq_findings_fingerprint"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)

    fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    tool: Mapped[str] = mapped_column(String, index=True)
    project: Mapped[str] = mapped_column(String, default="", index=True)
    source_id: Mapped[str | None] = mapped_column(String, nullable=True)
    component: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    component_version: Mapped[str | None] = mapped_column(String, nullable=True)
    title: Mapped[str] = mapped_column(String, index=True)
    severity: Mapped[str] = mapped_column(String)

    asset: Mapped[str] = mapped_column(String, index=True)
    asset_id: Mapped[str | None] = mapped_column(String, ForeignKey("assets.id"), nullable=True, index=True)
    asset_rel: Mapped["Asset"] = relationship(back_populates="findings")

    exposure: Mapped[str] = mapped_column(String, default="internal")
    criticality: Mapped[str] = mapped_column(String, default="medium")
    status: Mapped[str] = mapped_column(String, default="open", index=True)
    assignee: Mapped[str | None] = mapped_column(String, nullable=True, index=True)

    risk_score: Mapped[int] = mapped_column(Integer, default=1)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwe_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String, nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    references_json: Mapped[str] = mapped_column(Text, default="[]")
    tags_json: Mapped[str] = mapped_column(Text, default="[]")

    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    signal_id: Mapped[str] = mapped_column(String, index=True)

    comments: Mapped[list["Comment"]] = relationship(back_populates="finding", order_by="Comment.created_at.desc()")


class Comment(Base):
    __tablename__ = "comments"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(String, ForeignKey("findings.id"), index=True)
    finding: Mapped["Finding"] = relationship(back_populates="comments")

    author: Mapped[str] = mapped_column(String, default="system")
    content: Mapped[str] = mapped_column(Text)
    action_type: Mapped[str | None] = mapped_column(String, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ImportRun(Base):
    __tablename__ = "imports"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    parser: Mapped[str] = mapped_column(String, default="auto")
    filename: Mapped[str | None] = mapped_column(String, nullable=True)
    project: Mapped[str] = mapped_column(String, default="", index=True)
    actor: Mapped[str] = mapped_column(String)
    content_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String, default="processing", index=True)
    imported: Mapped[int] = mapped_column(Integer, default=0)
    new_findings: Mapped[int] = mapped_column(Integer, default=0)
    deduplicated: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    event_key: Mapped[str] = mapped_column(String, unique=True)
    finding_id: Mapped[str | None] = mapped_column(String, ForeignKey("findings.id"), nullable=True, index=True)
    channel: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="pending", index=True)
    payload: Mapped[str] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    claim_token: Mapped[str | None] = mapped_column(String, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    external_id: Mapped[str | None] = mapped_column(String, nullable=True)
    external_url: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
