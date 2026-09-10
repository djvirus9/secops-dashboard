"""Persist delivery intents in the same transaction as their findings."""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ..models import Finding, NotificationDelivery


def utcnow():
    return datetime.now(UTC).replace(tzinfo=None)


def configured_channels() -> list[str]:
    channels = []
    if os.environ.get("SLACK_WEBHOOK_URL"):
        channels.append("slack")
    if all(os.environ.get(key) for key in ("JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY")):
        channels.append("jira")
    return channels


def enqueue(db: Session, *, event_key: str, channel: str, payload: dict, finding_id: str | None = None):
    insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
    now = utcnow()
    statement = insert(NotificationDelivery).values(
        event_key=event_key, finding_id=finding_id, channel=channel,
        status="pending", payload=json.dumps(payload), attempts=0,
        next_attempt_at=now, created_at=now, updated_at=now,
    ).on_conflict_do_nothing(index_elements=[NotificationDelivery.event_key]).returning(NotificationDelivery.id)
    return db.execute(statement).scalar_one_or_none()


def enqueue_finding(db: Session, finding: Finding, *, event_id: str, is_new: bool):
    if finding.severity not in {"critical", "high"}:
        return
    payload = {
        "title": finding.title, "severity": finding.severity, "asset": finding.asset,
        "risk_score": finding.risk_score, "finding_id": finding.id, "tool": finding.tool,
        "is_new": is_new, "occurrences": finding.occurrences,
        "description": finding.description or "", "recommendation": finding.recommendation or "",
        "project": finding.project, "component": finding.component or "",
        "component_version": finding.component_version or "",
    }
    for channel in configured_channels():
        # One Jira ticket per finding, including findings that later escalate.
        key = f"jira:{finding.id}" if channel == "jira" else f"slack:{event_id}:{finding.id}"
        enqueue(db, event_key=key, channel=channel, payload=payload, finding_id=finding.id)


def serialize_delivery(row: NotificationDelivery) -> dict:
    return {
        "id": row.id, "finding_id": row.finding_id, "channel": row.channel,
        "status": row.status, "attempts": row.attempts, "last_error": row.last_error,
        "external_id": row.external_id, "external_url": row.external_url,
        "created_at": row.created_at.isoformat() + "Z",
        "updated_at": row.updated_at.isoformat() + "Z",
        "next_attempt_at": row.next_attempt_at.isoformat() + "Z",
    }
