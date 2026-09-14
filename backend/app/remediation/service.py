"""Explainable priority calculations and durable intelligence synchronization."""
from __future__ import annotations

from datetime import timedelta
import json
import logging
from uuid import uuid4

from sqlalchemy import and_, or_, select

from ..accounts import _lock_accounts
from ..db import SessionLocal
from ..models import (
    Finding, IntelligenceSyncState, RemediationPolicy, VulnerabilityIntelligence, _utcnow,
)
from . import client


logger = logging.getLogger(__name__)
SOURCES = ("cisa_kev", "first_epss")
LEASE_SECONDS = 300
DEFAULT_POLICY = {
    "critical_days": 7,
    "high_days": 30,
    "medium_days": 90,
    "low_days": 180,
    "info_days": 365,
    "kev_days": 7,
}
BASE_PRIORITY = {"critical": 40, "high": 30, "medium": 20, "low": 10, "info": 5}


def policy_values(db, project: str) -> dict[str, int]:
    row = db.get(RemediationPolicy, project) or db.get(RemediationPolicy, "")
    if row is None:
        return dict(DEFAULT_POLICY)
    return {name: int(getattr(row, name)) for name in DEFAULT_POLICY}


def priority_components(finding: Finding) -> tuple[int, list[dict]]:
    severity = (finding.severity or "info").lower()
    base = BASE_PRIORITY.get(severity, 5)
    reasons = [{"factor": f"{severity.title()} severity", "points": base}]
    if finding.kev:
        reasons.append({"factor": "Known exploited (CISA KEV)", "points": 30})
    if finding.exposure == "internet":
        reasons.append({"factor": "Internet exposed", "points": 15})
    if finding.criticality == "high":
        reasons.append({"factor": "High-criticality asset", "points": 10})
    if finding.epss_percentile is not None and finding.epss_percentile >= 0.9:
        reasons.append({"factor": "EPSS at or above 90th percentile", "points": 10})
    return min(100, sum(item["points"] for item in reasons)), reasons


def refresh_finding(db, finding: Finding, *, now=None) -> None:
    now = now or _utcnow()
    intelligence = db.get(VulnerabilityIntelligence, (finding.cve_id or "").upper()) if finding.cve_id else None
    if intelligence is None:
        finding.kev = False
        finding.kev_date_added = None
        finding.kev_due_date = None
        finding.kev_ransomware = False
        finding.epss_score = None
        finding.epss_percentile = None
        finding.intelligence_updated_at = None
    else:
        finding.kev = intelligence.kev
        finding.kev_date_added = intelligence.kev_date_added
        finding.kev_due_date = intelligence.kev_due_date
        finding.kev_ransomware = intelligence.kev_ransomware
        finding.epss_score = intelligence.epss_score
        finding.epss_percentile = intelligence.epss_percentile
        finding.intelligence_updated_at = intelligence.updated_at
    finding.priority_score, reasons = priority_components(finding)
    finding.priority_reasons_json = json.dumps(reasons, separators=(",", ":"))
    policy = policy_values(db, finding.project)
    severity_days = policy.get(f"{(finding.severity or 'info').lower()}_days", policy["info_days"])
    due_days = min(severity_days, policy["kev_days"]) if finding.kev else severity_days
    finding.remediation_due_at = finding.first_seen + timedelta(days=due_days)


def refresh_project(db, project: str | None = None) -> int:
    statement = select(Finding)
    if project is not None:
        statement = statement.where(Finding.project == project)
    rows = db.scalars(statement).all()
    now = _utcnow()
    for row in rows:
        refresh_finding(db, row, now=now)
    return len(rows)


def backfill_remediation() -> int:
    """Populate only rows from pre-v0.4 databases; new scores are never zero."""
    with SessionLocal.begin() as db:
        rows = db.scalars(select(Finding).where(Finding.priority_score == 0)).all()
        now = _utcnow()
        for row in rows:
            refresh_finding(db, row, now=now)
        return len(rows)


def ensure_sync_states(db) -> None:
    now = _utcnow()
    for source in SOURCES:
        if db.get(IntelligenceSyncState, source) is None:
            db.add(IntelligenceSyncState(source=source, enabled=False, interval_hours=24,
                                         status="idle", next_sync_at=now, updated_at=now))
    db.flush()


def queue_sources(sources: list[str]) -> None:
    now = _utcnow()
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        ensure_sync_states(db)
        for source in sources:
            row = db.get(IntelligenceSyncState, source)
            row.status = "queued"
            row.next_sync_at = now
            row.last_error = None
            row.updated_at = now


def claim_sync() -> dict | None:
    now = _utcnow()
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        ensure_sync_states(db)
        row = db.scalar(select(IntelligenceSyncState).where(
            or_(
                and_(IntelligenceSyncState.status == "queued", IntelligenceSyncState.next_sync_at <= now),
                and_(IntelligenceSyncState.enabled.is_(True),
                     IntelligenceSyncState.status != "syncing", IntelligenceSyncState.next_sync_at <= now),
                and_(IntelligenceSyncState.status == "syncing",
                     IntelligenceSyncState.claimed_at < now - timedelta(seconds=LEASE_SECONDS)),
            )
        ).order_by(IntelligenceSyncState.next_sync_at, IntelligenceSyncState.source).limit(1))
        if row is None:
            return None
        token = str(uuid4())
        row.status, row.claim_token, row.claimed_at, row.updated_at = "syncing", token, now, now
        task = {"source": row.source, "claim_token": token}
        if row.source == "first_epss":
            task["cve_ids"] = list(db.scalars(select(Finding.cve_id).where(
                Finding.cve_id.is_not(None)).distinct().order_by(Finding.cve_id)
                .limit(client.MAX_EPSS_CVES + 1)))
        return task


def _current_claim(db, task):
    row = db.get(IntelligenceSyncState, task["source"])
    if (row is None or row.status != "syncing" or row.claim_token != task["claim_token"]
            or row.claimed_at is None
            or row.claimed_at <= _utcnow() - timedelta(seconds=LEASE_SECONDS)):
        return None
    return row


def fail_sync(task: dict, message: str) -> None:
    now = _utcnow()
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        row = _current_claim(db, task)
        if row is None:
            return
        row.status = "failed"
        row.last_error = message[:500]
        row.claim_token = row.claimed_at = None
        row.next_sync_at = now + timedelta(hours=max(1, row.interval_hours))
        row.updated_at = now


def apply_feed(task: dict, items: list[dict]) -> bool:
    now = _utcnow()
    with SessionLocal.begin() as db:
        _lock_accounts(db)
        state = _current_claim(db, task)
        if state is None:
            return False
        if task["source"] == "cisa_kev":
            for row in db.scalars(select(VulnerabilityIntelligence).where(
                    VulnerabilityIntelligence.kev.is_(True))):
                row.kev = False
                row.kev_date_added = row.kev_due_date = None
                row.kev_ransomware = False
                row.kev_required_action = None
                row.kev_updated_at = now
                row.updated_at = now
            for item in items:
                row = db.get(VulnerabilityIntelligence, item["cve_id"])
                if row is None:
                    row = VulnerabilityIntelligence(cve_id=item["cve_id"])
                    db.add(row)
                row.kev = True
                row.kev_date_added = item["kev_date_added"]
                row.kev_due_date = item["kev_due_date"]
                row.kev_ransomware = item["kev_ransomware"]
                row.kev_required_action = item["kev_required_action"]
                row.kev_updated_at = row.updated_at = now
        else:
            # A successful response is authoritative for every requested CVE. Clear
            # old scores first so a removed record cannot remain as stale evidence.
            requested = {normalized for value in task.get("cve_ids", [])
                         if (normalized := client.normalize_cve(value))}
            if requested:
                for row in db.scalars(select(VulnerabilityIntelligence).where(
                        VulnerabilityIntelligence.cve_id.in_(requested))):
                    row.epss_score = row.epss_percentile = None
                    row.epss_updated_at = row.updated_at = now
            for item in items:
                row = db.get(VulnerabilityIntelligence, item["cve_id"])
                if row is None:
                    row = VulnerabilityIntelligence(cve_id=item["cve_id"])
                    db.add(row)
                row.epss_score = item["epss_score"]
                row.epss_percentile = item["epss_percentile"]
                row.epss_updated_at = row.updated_at = now
        db.flush()
        refresh_project(db)
        state.status = "succeeded"
        state.last_error = None
        state.last_synced_at = now
        state.record_count = len(items)
        state.claim_token = state.claimed_at = None
        state.next_sync_at = now + timedelta(hours=max(1, state.interval_hours))
        state.updated_at = now
    return True


def process_one() -> bool:
    task = claim_sync()
    if task is None:
        return False
    try:
        items = (client.fetch_kev() if task["source"] == "cisa_kev"
                 else client.fetch_epss(task.get("cve_ids", [])))
        apply_feed(task, items)
    except client.IntelligenceFetchError as exc:
        fail_sync(task, str(exc))
    except Exception:
        logger.error("Intelligence sync for %s failed", task["source"])
        fail_sync(task, "Unexpected intelligence sync failure; retry after checking connectivity")
    return True
