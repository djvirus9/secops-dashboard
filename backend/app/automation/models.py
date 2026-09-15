from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from ..models import _utcnow, _uuid


class AutomationPolicy(Base):
    __tablename__ = "automation_policies"

    project: Mapped[str] = mapped_column(String(255), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    warn_before_hours: Mapped[int] = mapped_column(Integer, default=24)
    reminder_hours: Mapped[int] = mapped_column(Integer, default=24)
    notify_slack: Mapped[bool] = mapped_column(Boolean, default=False)
    next_evaluation_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    last_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class OperationalAlert(Base):
    __tablename__ = "operational_alerts"
    __table_args__ = (UniqueConstraint("kind", "resource_id", name="uq_operational_alert_resource"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project: Mapped[str] = mapped_column(String(255), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    resource_id: Mapped[str] = mapped_column(String)
    condition: Mapped[str] = mapped_column(String(20))
    state: Mapped[str] = mapped_column(String(20), default="open", index=True)
    title: Mapped[str] = mapped_column(String(300))
    message: Mapped[str] = mapped_column(Text)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    team: Mapped[str | None] = mapped_column(String(100), nullable=True)
    escalation_contact: Mapped[str | None] = mapped_column(String(255), nullable=True)
    generation: Mapped[int] = mapped_column(Integer, default=1)
    notification_sequence: Mapped[int] = mapped_column(Integer, default=0)
    last_notified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
