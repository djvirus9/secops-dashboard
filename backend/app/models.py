from __future__ import annotations

from datetime import UTC, date, datetime
from uuid import uuid4

from sqlalchemy import Boolean, String, Integer, Float, Date, DateTime, Index, Text, ForeignKey, UniqueConstraint
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


class Team(Base):
    __tablename__ = "teams"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    contact: Mapped[str] = mapped_column(String(255), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ProjectProfile(Base):
    """Optional ownership metadata layered over existing project string keys."""

    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(255), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    team_id: Mapped[str | None] = mapped_column(String, ForeignKey("teams.id"), nullable=True, index=True)
    business_unit: Mapped[str] = mapped_column(String(255), default="")
    tier: Mapped[str] = mapped_column(String(20), default="medium")
    repository_url: Mapped[str] = mapped_column(String(500), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class CoverageExpectation(Base):
    __tablename__ = "coverage_expectations"
    __table_args__ = (
        UniqueConstraint("project", "source_type", "source", name="uq_coverage_expectation_source"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project: Mapped[str] = mapped_column(String(255), index=True)
    source_type: Mapped[str] = mapped_column(String(20))
    source: Mapped[str] = mapped_column(String(200))
    interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    required: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


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
    priority_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    priority_reasons_json: Mapped[str] = mapped_column(Text, default="[]")
    occurrences: Mapped[int] = mapped_column(Integer, default=1)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwe_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_date_added: Mapped[date | None] = mapped_column(Date, nullable=True)
    kev_due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    kev_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    intelligence_updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String, nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    references_json: Mapped[str] = mapped_column(Text, default="[]")
    tags_json: Mapped[str] = mapped_column(Text, default="[]")

    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    remediation_due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    risk_accepted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    risk_accepted_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    risk_accepted_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    risk_acceptance_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    disposition_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    duplicate_of_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    verification_requested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    verified_by: Mapped[str | None] = mapped_column(String(100), nullable=True)

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
    __table_args__ = (
        Index("ix_imports_coverage_latest", "project", "parser", "created_at"),
        Index("ix_imports_coverage_success", "project", "parser", "status", "completed_at"),
    )

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


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(16))
    # NULL grants all projects; a JSON list grants only its listed projects.
    projects_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuthThrottle(Base):
    __tablename__ = "auth_throttles"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)


class AuthLock(Base):
    __tablename__ = "auth_locks"

    # The identity service uses row 1 to serialize account lifecycle changes.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)


class SavedView(Base):
    __tablename__ = "saved_views"
    __table_args__ = (UniqueConstraint("user_id", "name", name="uq_saved_views_user_name"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    filters_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(100))
    object_type: Mapped[str] = mapped_column(String(100))
    object_id: Mapped[str | None] = mapped_column(String, nullable=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)


class ScannerToken(Base):
    __tablename__ = "scanner_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(100))
    project: Mapped[str] = mapped_column(String(255), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class VulnerabilityIntelligence(Base):
    __tablename__ = "vulnerability_intelligence"

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_date_added: Mapped[date | None] = mapped_column(Date, nullable=True)
    kev_due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    kev_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev_updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    epss_updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class RemediationPolicy(Base):
    __tablename__ = "remediation_policies"

    # Empty project is the deployment-wide fallback. Exact project rows override it.
    project: Mapped[str] = mapped_column(String(255), primary_key=True)
    critical_days: Mapped[int] = mapped_column(Integer, default=7)
    high_days: Mapped[int] = mapped_column(Integer, default=30)
    medium_days: Mapped[int] = mapped_column(Integer, default=90)
    low_days: Mapped[int] = mapped_column(Integer, default=180)
    info_days: Mapped[int] = mapped_column(Integer, default=365)
    kev_days: Mapped[int] = mapped_column(Integer, default=7)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class IntelligenceSyncState(Base):
    __tablename__ = "intelligence_sync_states"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    status: Mapped[str] = mapped_column(String(20), default="idle")
    next_sync_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    claim_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
