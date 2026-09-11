"""Leased sync jobs; complete snapshots commit atomically with their findings."""
from __future__ import annotations

from dataclasses import asdict
from datetime import timedelta
import hashlib
import json
import logging
from uuid import uuid4

from sqlalchemy import and_, delete, or_, select, update

from ..accounts import _lock_accounts
from ..db import SessionLocal
from ..models import Comment, Finding, ImportRun, Signal, _utcnow
from ..notifications.outbox import enqueue_finding
from .models import GitHubAlert, GitHubConnection, GitHubSyncRun
from .routes import configured

logger = logging.getLogger(__name__)
LEASE_SECONDS = 300
STATE_TO_STATUS = {"open": "open", "fixed": "resolved", "dismissed": "closed", "auto_dismissed": "closed"}


def claim_sync() -> dict | None:
    if not configured():
        return None
    now = _utcnow()
    with SessionLocal.begin() as db:
        # A short database lock serializes configuration changes and claims on
        # SQLite and PostgreSQL. No network requests run inside this transaction.
        _lock_accounts(db)
        row = db.scalar(select(GitHubConnection).where(
            GitHubConnection.enabled.is_(True),
            or_(and_(GitHubConnection.status != "syncing", GitHubConnection.next_sync_at <= now),
                and_(GitHubConnection.status == "syncing",
                     GitHubConnection.claimed_at < now - timedelta(seconds=LEASE_SECONDS))),
        ).order_by(GitHubConnection.next_sync_at, GitHubConnection.id).limit(1))
        if row is None:
            return None
        if row.claim_token:
            previous = db.get(GitHubSyncRun, row.claim_token)
            if previous and previous.status == "syncing":
                previous.status, previous.completed_at = "interrupted", now
                previous.error = "Worker interrupted; a fresh sync was queued"
        token = str(uuid4())
        row.status, row.claim_token, row.claimed_at, row.updated_at = "syncing", token, now, now
        run = GitHubSyncRun(id=token, connection_id=row.id, started_at=now)
        db.add(run)
        db.flush()
        # Keep a bounded operational history. Findings and import records have
        # their own durable histories and never depend on these run rows.
        old_ids = list(db.scalars(select(GitHubSyncRun.id).where(GitHubSyncRun.connection_id == row.id)
                                 .order_by(GitHubSyncRun.started_at.desc(), GitHubSyncRun.id.desc())
                                 .offset(100)))
        if old_ids:
            db.execute(delete(GitHubSyncRun).where(GitHubSyncRun.id.in_(old_ids)))
        return {"id": row.id, "claim_token": token, "repository": row.repository,
                "project": row.project, "sources": json.loads(row.sources_json)}


def _current_claim(db, task):
    row = db.get(GitHubConnection, task["id"])
    if (row is None or not row.enabled or row.claim_token != task["claim_token"]
            or row.status != "syncing" or row.claimed_at is None
            or row.claimed_at <= _utcnow() - timedelta(seconds=LEASE_SECONDS)):
        return None
    return row


def _finish(row, run, now, *, error=None, retry_after=None):
    row.status = run.status = "failed" if error else "succeeded"
    row.last_error = run.error = error
    row.claim_token, row.claimed_at, row.updated_at, run.completed_at = None, None, now, now
    delay = max(row.interval_minutes * 60, min(max(retry_after or 0, 0), 86400))
    row.next_sync_at = now + timedelta(seconds=delay)
    if error is None:
        row.last_synced_at = now


def fail_sync(task, message, retry_after=None):
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        row = _current_claim(db, task)
        if row is not None:
            _finish(row, db.get(GitHubSyncRun, task["claim_token"]), _utcnow(),
                    error=message, retry_after=retry_after)


def apply_snapshot(task: dict, alerts: list) -> bool:
    # Shared asset/risk rules remain the same for uploads and synced alerts.
    # Deferred import avoids a router -> service -> application import cycle.
    from ..main import _get_or_create_asset, compute_risk_score

    now = _utcnow()
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        connection = _current_claim(db, task)
        if connection is None:
            return False
        run = db.get(GitHubSyncRun, task["claim_token"])
        run.imported = len(alerts)
        links = {(row.source, row.number): row for row in db.scalars(
            select(GitHubAlert).where(GitHubAlert.connection_id == connection.id))}
        changes = []
        observed_ids = []
        for alert in alerts:
            data = asdict(alert)
            digest = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            link = links.get((alert.source, alert.number))
            if link is not None:
                link.last_synced_at = now
                observed_ids.append(link.finding_id)
            if link is None or link.content_hash != digest:
                changes.append((alert, data, digest, link))
        if changes:
            asset = _get_or_create_asset(db, key=connection.repository, name=connection.repository,
                                         environment="unknown", owner="", criticality="medium", exposure="internal",
                                         now=now, project=connection.project)
            import_run = ImportRun(parser="github-sync", project=connection.project,
                                   actor=f"github-sync:{connection.id}", status="completed", imported=len(changes),
                                   content_sha256=hashlib.sha256(json.dumps([entry[2] for entry in changes]).encode()).hexdigest(),
                                   completed_at=now)
            db.add(import_run)
            db.flush()
            new_count = 0
            for alert, data, digest, link in changes:
                signal = Signal(tool=f"github-{alert.source.replace('_', '-')}", import_id=import_run.id,
                                payload=json.dumps(data), created_at=now)
                db.add(signal)
                db.flush()
                category = "code-scanning" if alert.source == "code_scanning" else "dependabot"
                reference = f"https://github.com/{connection.repository}/security/{category}/{alert.number}"
                values = {name: data[name] for name in (
                    "title", "severity", "description", "recommendation", "component", "component_version",
                    "file_path", "line_number", "cve_id", "cwe_id", "cvss_score",
                )}
                values.update(tool=signal.tool, project=connection.project, asset=asset.key, asset_id=asset.id,
                              source_id=reference, exposure=asset.exposure, criticality=asset.criticality,
                              risk_score=compute_risk_score(alert.severity, asset.exposure, asset.criticality),
                              references_json=json.dumps([reference]),
                              tags_json=json.dumps(["github-sync", f"github-state:{alert.state}"]),
                              last_seen=now, signal_id=signal.id)
                is_new = link is None
                reopened = False
                if is_new:
                    identity = json.dumps(["github-sync-v1", connection.repository, alert.source, alert.number,
                                           connection.project], separators=(",", ":"))
                    finding = Finding(fingerprint=hashlib.sha256(identity.encode()).hexdigest(),
                                      status=STATE_TO_STATUS[alert.state], first_seen=now, occurrences=1, **values)
                    db.add(finding)
                    db.flush()
                    link = GitHubAlert(connection_id=connection.id, source=alert.source, number=alert.number,
                                       finding_id=finding.id, source_state=alert.state, content_hash=digest,
                                       last_synced_at=now)
                    db.add(link)
                    new_count += 1
                else:
                    finding = db.scalar(select(Finding).where(Finding.id == link.finding_id).with_for_update())
                    for name, value in values.items():
                        setattr(finding, name, value)
                    # A repeated open observation must not undo an analyst's
                    # status. Only an actual source state transition changes it.
                    if link.source_state != alert.state:
                        old_status = finding.status
                        finding.status = STATE_TO_STATUS[alert.state]
                        reopened = finding.status == "open" and old_status in {"closed", "resolved"}
                        db.add(Comment(finding_id=finding.id, author="GitHub sync", action_type="status_change",
                                       content=f"GitHub alert changed from {link.source_state} to {alert.state}; "
                                               f"status changed from {old_status} to {finding.status}"))
                    link.source_state, link.content_hash = alert.state, digest
                if finding.status == "open" and (is_new or reopened):
                    enqueue_finding(db, finding, event_id=signal.id, is_new=is_new)
            import_run.new_findings = run.new_findings = new_count
            import_run.deduplicated = run.updated = len(changes) - new_count
        # Last seen means observed, including an unchanged replay. Update it
        # without altering triage, occurrence counts or creating more signals.
        # Do this after asset locking above to retain the app's lock order.
        for offset in range(0, len(observed_ids), 500):
            db.execute(update(Finding).where(Finding.id.in_(observed_ids[offset:offset + 500]))
                       .values(last_seen=now))
        # Missing alerts do not imply fixes: visibility and GitHub retention can
        # change. Only explicit source states above can close existing findings.
        _finish(connection, run, now)
    return True


def process_one() -> bool:
    from . import client

    task = claim_sync()
    if task is None:
        return False
    try:
        alerts = client.fetch_alerts(task["repository"], task["sources"])
        apply_snapshot(task, alerts)
    except client.GitHubFetchError as exc:
        fail_sync(task, exc.message, exc.retry_after)
    except Exception:
        # Neither upstream response bodies nor exception text are safe to log.
        logger.error("GitHub sync %s failed", task["id"])
        fail_sync(task, "Unexpected sync failure; check server configuration and retry")
    return True
