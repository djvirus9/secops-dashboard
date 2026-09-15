"""Evaluate bounded project policies; alert and outbox changes commit atomically.

No external requests run in these transactions. An acknowledgement suppresses
reminders, not the underlying health condition. A new condition reopens the alert.
"""
from __future__ import annotations

import json
import logging
from datetime import timedelta

from sqlalchemy import or_, select, update

from ..db import SessionLocal
from ..finding_query import ACTIVE_FINDING_STATUSES
from ..models import AuditEvent, CoverageExpectation, Finding, ProjectProfile, Team, _utcnow
from ..notifications.outbox import configured_channels, enqueue
from ..operational import _coverage_row
from .models import AutomationPolicy, OperationalAlert

logger = logging.getLogger(__name__)
EVALUATION_SECONDS = 300
MAX_FINDINGS = 10_000
MAX_COVERAGE = 1_000
MAX_ALERTS = 20_000


def _activity(db, alert, action, now, **details):
    db.add(AuditEvent(actor="automation", action=f"automation.alert.{action}",
                      object_type="operational_alert", object_id=alert.id,
                      details_json=json.dumps({"project": alert.project, "condition": alert.condition,
                                               "generation": alert.generation, **details}), created_at=now))


def resolve_alert(db, row, now, reason="condition cleared"):
    if row.state != "resolved":
        row.state, row.resolved_at = "resolved", now
        _activity(db, row, "resolved", now, reason=reason)


def _evaluate_policy(db, policy, now):
    profile = db.get(ProjectProfile, policy.project)
    team = db.get(Team, profile.team_id) if profile and profile.team_id else None
    team_name = team.name if team and team.active else None
    contact = team.contact if team and team.active else None
    findings = db.scalars(select(Finding).where(
        Finding.project == policy.project,
        Finding.status.in_(ACTIVE_FINDING_STATUSES),
        Finding.remediation_due_at <= now + timedelta(hours=policy.warn_before_hours),
        or_(Finding.risk_accepted_until.is_(None), Finding.risk_accepted_until <= now),
    ).order_by(Finding.id).limit(MAX_FINDINGS + 1)).all()
    coverage = db.scalars(select(CoverageExpectation).where(
        CoverageExpectation.project == policy.project,
        CoverageExpectation.enabled.is_(True), CoverageExpectation.required.is_(True),
    ).order_by(CoverageExpectation.id).limit(MAX_COVERAGE + 1)).all()
    existing = db.scalars(select(OperationalAlert).where(
        OperationalAlert.project == policy.project,
    ).order_by(OperationalAlert.id).limit(MAX_ALERTS + 1).with_for_update()).all()
    if len(findings) > MAX_FINDINGS or len(coverage) > MAX_COVERAGE or len(existing) > MAX_ALERTS:
        # Never interpret a truncated scan as recovery of omitted alerts.
        raise ValueError("Project exceeds the bounded automation evaluation limit; no alerts were changed")
    expected = {}
    for finding in findings:
        condition = "overdue" if finding.remediation_due_at < now else "due_soon"
        expected[("sla", finding.id)] = {
            "condition": condition,
            "title": f"SLA {'overdue' if condition == 'overdue' else 'due soon'}: {finding.title}"[:300],
            "message": f"Remediation deadline: {finding.remediation_due_at.isoformat()}Z. "
                       f"Status: {finding.status}. Owner: {finding.assignee or 'unassigned'}. "
                       "A ticket closure alone is not verification evidence.",
            "owner": finding.assignee,
        }
    for expectation in coverage:
        health = _coverage_row(db, expectation, now, team_name)["health"]
        if health in {"missing", "stale", "failing"}:
            expected[("coverage", expectation.id)] = {
                "condition": health,
                "title": f"Required source {health}: {expectation.source}"[:300],
                "message": f"{expectation.source_type} source {expectation.source} must report successfully "
                           f"every {expectation.interval_hours} hours. Check the Coverage and Imports pages; "
                           "missing results do not prove that findings are fixed.",
                "owner": None,
            }
    by_key = {(row.kind, row.resource_id): row for row in existing}
    for key, row in by_key.items():
        if key not in expected:
            resolve_alert(db, row, now)
    slack_ready = policy.notify_slack and "slack" in configured_channels()
    for (kind, resource_id), data in expected.items():
        row = by_key.get((kind, resource_id))
        if row is None:
            row = OperationalAlert(project=policy.project, kind=kind, resource_id=resource_id,
                                   state="open", generation=1, notification_sequence=0,
                                   first_seen_at=now, last_seen_at=now, **data)
            db.add(row)
            db.flush()
            _activity(db, row, "opened", now)
        elif row.state == "resolved" or row.condition != data["condition"]:
            row.state, row.condition = "open", data["condition"]
            row.generation += 1
            row.first_seen_at = now
            row.resolved_at = row.acknowledged_at = row.acknowledged_by = row.last_notified_at = None
            _activity(db, row, "reopened", now)
        for field, value in data.items():
            setattr(row, field, value)
        row.team, row.escalation_contact, row.last_seen_at = team_name, contact, now
        if (slack_ready and row.state == "open" and (row.last_notified_at is None
                or row.last_notified_at <= now - timedelta(hours=policy.reminder_hours))):
            row.notification_sequence += 1
            payload = {
                "event_type": "operational_alert", "alert_id": row.id,
                "title": row.title, "project": row.project, "kind": row.kind,
                "condition": row.condition, "message": row.message,
                "owner": row.owner, "team": row.team, "escalation_contact": row.escalation_contact,
                "resource_id": row.resource_id, "generation": row.generation,
            }
            enqueue(db, event_key=f"operational:{row.id}:{row.generation}:{row.notification_sequence}",
                    channel="slack", payload=payload,
                    finding_id=resource_id if kind == "sla" else None)
            row.last_notified_at = now
    policy.last_evaluated_at, policy.last_error = now, None


def process_one() -> bool:
    now = _utcnow()
    project = None
    try:
        with SessionLocal.begin() as db:
            project = db.scalar(select(AutomationPolicy.project).where(
                AutomationPolicy.enabled.is_(True), AutomationPolicy.next_evaluation_at <= now,
            ).order_by(AutomationPolicy.next_evaluation_at, AutomationPolicy.project).limit(1))
            if project is None:
                return False
            # Conditional write is a claim on both SQLite and PostgreSQL. Keep
            # this transaction short and local; competing evaluators skip it.
            claimed = db.execute(update(AutomationPolicy).where(
                AutomationPolicy.project == project, AutomationPolicy.enabled.is_(True),
                AutomationPolicy.next_evaluation_at <= now,
            ).values(next_evaluation_at=now + timedelta(seconds=EVALUATION_SECONDS)))
            if claimed.rowcount != 1:
                return False
            policy = db.get(AutomationPolicy, project)
            _evaluate_policy(db, policy, now)
        return True
    except ValueError as exc:
        error = str(exc)
    except Exception:
        logger.error("Operational policy evaluation failed")
        if project is None:
            # A missing schema or unreachable database is not completed work.
            # Let the worker back off and withhold its health heartbeat.
            raise
        error = "Evaluation failed; previous alerts were retained. Check worker logs."
    if project is not None:
        with SessionLocal.begin() as db:
            # A concurrent successful evaluation or policy change wins over a
            # stale failure report after rollback.
            db.execute(update(AutomationPolicy).where(
                AutomationPolicy.project == project, AutomationPolicy.next_evaluation_at <= now,
            ).values(last_error=error, next_evaluation_at=now + timedelta(seconds=EVALUATION_SECONDS)))
    return True
