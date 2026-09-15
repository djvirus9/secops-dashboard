"""Durable progress polling and explicitly approved one-field pushes.

No network operation holds a database transaction open. Pulls compare workflow
snapshots before applying changes. Pushes compare both local and Jira snapshots
before sending, then recheck local state afterwards; Jira does not offer an atomic
cross-system compare-and-swap, so concurrent changes are surfaced for review.
"""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from ..accounts import _lock_accounts
from ..db import SessionLocal
from ..models import AuditEvent, Comment, Finding, NotificationDelivery, User, _utcnow
from ..ownership import assignee_is_eligible
from . import client
from .models import JiraIssueLink, JiraSyncControl, JiraUserMapping

LEASE_SECONDS = 120
MAX_ATTEMPTS = 5
STATUS_TARGETS = {"open": "new", "investigating": "indeterminate", "verification_pending": "done"}
REMOTE_TARGETS = {"new": "open", "indeterminate": "investigating", "done": "verification_pending"}


def timestamp(value):
    return value.isoformat() + "Z" if value else None


def serialize_link(row: JiraIssueLink) -> dict:
    return {"finding_id": row.finding_id, "issue_key": row.issue_key,
            "url": row.base_url + "/browse/" + row.issue_key,
            "remote_status": row.remote_status, "remote_status_category": row.remote_status_category,
            "remote_assignee": row.remote_assignee, "remote_updated_at": row.remote_updated_at,
            "last_synced_at": timestamp(row.last_synced_at), "next_sync_at": timestamp(row.next_sync_at),
            "status": row.status, "operation": row.operation, "last_error": row.last_error}


def eligible(user: User | None, project: str) -> bool:
    return user is not None and assignee_is_eligible(user, project)


def account_for_assignee(db, finding: Finding) -> str | None:
    if not finding.assignee:
        return None
    user = db.scalar(select(User).where(User.username == finding.assignee))
    if not eligible(user, finding.project):
        raise client.JiraError("The local assignee is no longer eligible for this project")
    mapping = db.get(JiraUserMapping, user.id)
    if mapping is None or not mapping.active:
        raise client.JiraError("An administrator must map this assignee to a Jira account first")
    return mapping.jira_account_id


def preview(db, finding: Finding) -> dict:
    try:
        account_for_assignee(db, finding)
        mapped = True
    except client.JiraError:
        mapped = False
    return {"local_status": finding.status, "local_assignee": finding.assignee,
            "status_target_category": STATUS_TARGETS.get(finding.status), "assignee_mapped": mapped}


def workflow_snapshot(db, finding: Finding) -> str:
    # Activity identity also detects same-value ABA triage. Scanner repeat
    # observations change last_seen/occurrences even when status stays open.
    comment_id = db.scalar(select(Comment.id).where(Comment.finding_id == finding.id)
                           .order_by(Comment.created_at.desc(), Comment.id.desc()).limit(1))
    fields = ("project", "status", "assignee", "last_seen", "occurrences", "resolved_at",
              "verification_requested_at", "verified_at", "verified_by", "disposition_reason",
              "duplicate_of_id", "risk_accepted_until", "risk_accepted_at")
    value = {name: str(getattr(finding, name)) for name in fields}
    value["comment_id"] = comment_id
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _audit(db, finding_id, action, details=None, *, actor="jira-sync", user_id=None):
    db.add(AuditEvent(actor=actor, user_id=user_id, action=action, object_type="finding",
                      object_id=finding_id, details_json=json.dumps(details or {})))


def _insert(db, model):
    return pg_insert(model) if db.get_bind().dialect.name == "postgresql" else sqlite_insert(model)


def _delivery_filters(config):
    # Filter tenant and valid issue evidence before LIMIT, so old-tenant or
    # malformed deliveries cannot permanently occupy the bounded discovery
    # window. The final Python validation below remains defense in depth.
    return (
        NotificationDelivery.channel == "jira", NotificationDelivery.status == "sent",
        NotificationDelivery.finding_id.is_not(None),
        NotificationDelivery.external_id.regexp_match("^" + client.KEY_PATTERN + "$"),
        ~NotificationDelivery.external_id.contains("\n"),
        NotificationDelivery.external_url == config.base_url + "/browse/" + NotificationDelivery.external_id,
    )


def discover_link(db, finding_id: str, config: client.Settings) -> JiraIssueLink | None:
    row = db.get(JiraIssueLink, finding_id)
    if row is not None:
        return row
    delivery = db.scalar(select(NotificationDelivery).where(
        NotificationDelivery.finding_id == finding_id, *_delivery_filters(config),
    ).order_by(NotificationDelivery.created_at, NotificationDelivery.id).limit(1))
    if (delivery is None or not client.valid_key(delivery.external_id)
            or delivery.external_url != config.base_url + "/browse/" + delivery.external_id):
        return None
    # The immutable tenant/key pair is derived only from successful delivery
    # evidence. A changed server tenant cannot redirect an existing issue link.
    inserted = db.execute(_insert(db, JiraIssueLink).values(
        finding_id=finding_id, issue_key=delivery.external_id, base_url=config.base_url,
        next_sync_at=_utcnow() - timedelta(seconds=1),
    ).on_conflict_do_nothing(index_elements=["finding_id"]).returning(JiraIssueLink.finding_id)).scalar()
    if inserted:
        _audit(db, finding_id, "jira.link", {"issue_key": delivery.external_id})
    return db.get(JiraIssueLink, finding_id)


def _discover(db, config):
    # At most twenty valid, distinct finding links are considered per tick.
    statement = (select(NotificationDelivery.finding_id)
                 .join(Finding, Finding.id == NotificationDelivery.finding_id).where(
                     *_delivery_filters(config),
                     ~NotificationDelivery.finding_id.in_(select(JiraIssueLink.finding_id)),
                 ).group_by(NotificationDelivery.finding_id)
                 .order_by(func.min(NotificationDelivery.created_at), NotificationDelivery.finding_id).limit(20))
    candidates = db.scalars(statement).all()
    for finding_id in candidates:
        discover_link(db, finding_id, config)


def _claim() -> dict | None:
    config = client.settings()
    with SessionLocal.begin() as db:
        # The same short lifecycle gate is acquired before any row access by
        # queueing, triage, account changes, claims and claim completion. This
        # prevents stale queue reads from overwriting a newly claimed operation.
        _lock_accounts(db)
        now = _utcnow()
        expired = now - timedelta(seconds=LEASE_SECONDS)
        db.execute(_insert(db, JiraSyncControl).values(id=1, next_request_at=now)
                   .on_conflict_do_nothing(index_elements=["id"]))
        token = str(uuid4())
        changed = db.execute(update(JiraSyncControl).where(
            JiraSyncControl.id == 1, JiraSyncControl.next_request_at <= now,
            or_(JiraSyncControl.claim_token.is_(None), JiraSyncControl.claimed_at < expired),
        ).values(claim_token=token, claimed_at=now))
        if changed.rowcount != 1:
            return None
        # Interrupted writes are never automatically replayed. Reads are safe
        # to retry, and a late result cannot complete after this token changes.
        db.execute(update(JiraIssueLink).where(
            JiraIssueLink.status == "syncing", JiraIssueLink.claimed_at < expired,
            JiraIssueLink.operation != "pull",
        ).values(status="needs_review", claim_token=None, claimed_at=None,
                 last_error="Push outcome unknown; inspect Jira and pull before another push", updated_at=now))
        db.execute(update(JiraIssueLink).where(
            JiraIssueLink.status == "syncing", JiraIssueLink.claimed_at < expired,
            JiraIssueLink.operation == "pull",
        ).values(status="idle", claim_token=None, claimed_at=None, next_sync_at=now, updated_at=now))
        _discover(db, config)
        row = db.scalar(select(JiraIssueLink).where(
            JiraIssueLink.status.in_(["idle", "queued"]), JiraIssueLink.next_sync_at <= now,
        ).order_by(JiraIssueLink.next_sync_at, JiraIssueLink.finding_id).limit(1))
        if row is None:
            db.execute(update(JiraSyncControl).where(JiraSyncControl.id == 1)
                       .values(claim_token=None, claimed_at=None, next_request_at=now + timedelta(seconds=5)))
            return None
        finding = db.get(Finding, row.finding_id)
        if finding is None:
            return None
        row.status, row.claim_token, row.claimed_at = "syncing", token, now
        row.updated_at, row.attempts = now, row.attempts + 1
        snapshot = workflow_snapshot(db, finding)
        return {"finding_id": row.finding_id, "issue_key": row.issue_key, "base_url": row.base_url,
                "token": token, "operation": row.operation, "attempts": row.attempts,
                "pending": json.loads(row.pending_json), "snapshot": snapshot,
                "remote": {"status_id": row.remote_status_id, "assignee_id": row.remote_assignee_id,
                           "updated_at": row.remote_updated_at}}


def _current_claim(db, task):
    _lock_accounts(db)
    # Consistent order with the API: lifecycle gate -> finding -> issue link.
    # These locks end before every network operation.
    db.execute(update(Finding).where(Finding.id == task["finding_id"]).values(status=Finding.status))
    # UPDATE provides an actual row write lock on SQLite as well as PostgreSQL.
    locked = db.execute(update(JiraIssueLink).where(
        JiraIssueLink.finding_id == task["finding_id"], JiraIssueLink.claim_token == task["token"],
        JiraIssueLink.status == "syncing",
        JiraIssueLink.claimed_at >= _utcnow() - timedelta(seconds=LEASE_SECONDS),
    ).values(updated_at=JiraIssueLink.updated_at))
    if locked.rowcount != 1:
        return None, None
    control = db.get(JiraSyncControl, 1)
    if control is None or control.claim_token != task["token"]:
        return None, None
    return db.get(JiraIssueLink, task["finding_id"]), db.get(Finding, task["finding_id"])


def _validate_push(db, task, finding):
    pending = task["pending"]
    if workflow_snapshot(db, finding) != pending["snapshot"]:
        raise client.JiraError("Local finding changed; pull and review before pushing again")
    if pending.get("user_id"):
        user = db.get(User, pending["user_id"])
        if not eligible(user, finding.project):
            raise client.JiraError("The requesting user no longer has write access to this project")
    if task["operation"] == "push_assignee":
        account = account_for_assignee(db, finding)
        if account != pending.get("account_id"):
            raise client.JiraError("The Jira identity mapping changed; review before pushing again")


def _execute(task) -> dict:
    config = client.settings()
    if config.base_url != task["base_url"]:
        raise client.JiraError("Jira tenant changed; restore the original tenant before syncing this link")
    jira = client.JiraClient(config)
    if task["operation"] == "pull":
        return {"remote": jira.issue(task["issue_key"]), "pushed": False}
    with SessionLocal.begin() as db:
        row, finding = _current_claim(db, task)
        if row is None or finding is None:
            raise client.JiraError("Sync claim expired; refresh before retrying")
        _validate_push(db, task, finding)
    current = jira.issue(task["issue_key"])
    expected = task["pending"]["remote"]
    if any(current[key] != expected[key] for key in ("status_id", "assignee_id", "updated_at")):
        raise client.JiraError("Jira changed since the last pull; pull and review before pushing again")
    # Recheck after the remote read, immediately before outbound mutation.
    with SessionLocal.begin() as db:
        row, finding = _current_claim(db, task)
        if row is None or finding is None:
            raise client.JiraError("Sync claim expired; refresh before retrying")
        _validate_push(db, task, finding)
    if task["operation"] == "push_status":
        target = task["pending"]["category"]
        if current["category"] != target:
            jira.transition(task["issue_key"], target)
    elif task["operation"] == "push_assignee":
        if current["assignee_id"] != task["pending"].get("account_id"):
            jira.assign(task["issue_key"], task["pending"].get("account_id"))
    else:
        raise client.JiraError("Unsupported Jira operation")
    # A successful write is not retried if its follow-up read fails.
    try:
        after = jira.issue(task["issue_key"])
    except client.JiraError as exc:
        raise client.JiraError("Push sent, but refresh failed; inspect Jira and pull before another push",
                               uncertain=True) from exc
    if ((task["operation"] == "push_status" and after["category"] != task["pending"]["category"])
            or (task["operation"] == "push_assignee" and after["assignee_id"] != task["pending"].get("account_id"))):
        raise client.JiraError("Push sent, but Jira does not show the requested value; inspect Jira and pull again",
                               uncertain=True)
    return {"remote": after, "pushed": True}


def _apply_pull(db, row, finding, remote, snapshot) -> str | None:
    notes = []
    unchanged = workflow_snapshot(db, finding) == snapshot
    baseline = json.loads(row.local_snapshot_json)
    initialized = row.remote_updated_at is not None
    if initialized and not unchanged:
        notes.append("Local finding changed during the pull; remote progress recorded without changing local triage")
    if initialized and unchanged:
        changed_status = remote["status_id"] != row.remote_status_id
        changed_owner = remote["assignee_id"] != row.remote_assignee_id
        # Terminal dispositions and verified evidence are always owned locally.
        if changed_status and finding.status in STATUS_TARGETS and finding.verified_at is None:
            if finding.status != baseline.get("status"):
                notes.append("Both local and Jira status changed; review the conflict")
            else:
                target = REMOTE_TARGETS[remote["category"]]
                if target != finding.status:
                    old = finding.status
                    finding.status, finding.resolved_at = target, None
                    finding.verification_requested_at = _utcnow() if target == "verification_pending" else None
                    finding.verified_at, finding.verified_by = None, None
                    db.add(Comment(finding_id=finding.id, author="jira-sync", action_type="status_change",
                                   content=f"Jira {row.issue_key}: status changed from '{old}' to '{target}'. "
                                           "Jira completion is not verified remediation."))
                    _audit(db, finding.id, "jira.pull.status", {"from": old, "to": target, "issue_key": row.issue_key})
        if changed_owner and finding.status in STATUS_TARGETS:
            if finding.assignee != baseline.get("assignee"):
                notes.append("Both local and Jira assignee changed; review the conflict")
            else:
                new_assignee = None
                can_assign = remote["assignee_id"] is None
                if remote["assignee_id"] is not None:
                    mapping = db.scalar(select(JiraUserMapping).where(
                        JiraUserMapping.jira_account_id == remote["assignee_id"], JiraUserMapping.active.is_(True)))
                    user = db.get(User, mapping.user_id) if mapping else None
                    if eligible(user, finding.project):
                        new_assignee, can_assign = user.username, True
                if not can_assign:
                    notes.append("Remote assignee has no eligible local identity mapping; local owner retained")
                elif finding.assignee != new_assignee:
                    old = finding.assignee
                    finding.assignee = new_assignee
                    db.add(Comment(finding_id=finding.id, author="jira-sync", action_type="assignee_change",
                                   content=f"Jira {row.issue_key}: assignee changed from '{old or 'unassigned'}' "
                                           f"to '{new_assignee or 'unassigned'}'."))
                    _audit(db, finding.id, "jira.pull.assignee", {"from": old, "to": new_assignee})
    # A routine unchanged poll must not make an unresolved conflict disappear.
    # A subsequent explicit local decision, remote transition, or successful
    # approved push establishes a new baseline. Network errors are not stored
    # in this baseline, so successful recovery still clears transient failures.
    if (not notes and baseline.get("conflict")
            and finding.status == baseline.get("status") and finding.assignee == baseline.get("assignee")
            and remote["status_id"] == row.remote_status_id and remote["assignee_id"] == row.remote_assignee_id):
        notes.append(baseline["conflict"])
    return "; ".join(notes)[:500] or None


def _finish(task, result=None, error: client.JiraError | None = None):
    now = _utcnow()
    with SessionLocal.begin() as db:
        row, finding = _current_claim(db, task)
        if row is None or finding is None:
            return
        if error:
            retry = error.retry_after is not None and task["attempts"] < MAX_ATTEMPTS and not error.uncertain
            row.status = "needs_review" if error.uncertain else "queued" if retry else "failed"
            row.last_error = str(error)[:500]
            delay = max(error.retry_after or 0, min(30 * 2 ** min(task["attempts"] - 1, 7), 3600))
            row.next_sync_at = now + timedelta(seconds=delay)
            _audit(db, finding.id, "jira.sync.error", {"operation": task["operation"], "status": row.status,
                                                     "error": row.last_error})
        else:
            remote = result["remote"]
            if result["pushed"]:
                row.last_error = None if workflow_snapshot(db, finding) == task["pending"]["snapshot"] else (
                    "Push was sent while local triage changed; inspect both systems before another push")
                _audit(db, finding.id, "jira.push.complete", {"operation": task["operation"],
                           "issue_key": row.issue_key, "conflict": row.last_error is not None},
                       actor=task["pending"]["actor"], user_id=task["pending"].get("user_id"))
            else:
                row.last_error = _apply_pull(db, row, finding, remote, task["snapshot"])
                _audit(db, finding.id, "jira.pull.complete", {"issue_key": row.issue_key,
                           "remote_status": remote["status"], "conflict": row.last_error is not None})
            row.remote_status_id, row.remote_status = remote["status_id"], remote["status"]
            row.remote_status_category = remote["category"]
            row.remote_assignee_id, row.remote_assignee = remote["assignee_id"], remote["assignee"]
            row.remote_updated_at = remote["updated_at"]
            row.local_snapshot_json = json.dumps({"status": finding.status, "assignee": finding.assignee,
                                                  "conflict": row.last_error})
            row.last_synced_at, row.next_sync_at = now, now + timedelta(minutes=client.interval_minutes())
            row.status, row.operation, row.pending_json, row.attempts = "idle", "pull", "{}", 0
        row.claim_token, row.claimed_at, row.updated_at = None, None, now
        db.execute(update(JiraSyncControl).where(JiraSyncControl.id == 1,
                   JiraSyncControl.claim_token == task["token"]).values(
                       claim_token=None, claimed_at=None,
                       next_request_at=now + timedelta(seconds=error.retry_after if error and error.retry_after else 1)))


def process_one() -> bool:
    if not client.enabled() or not client.configured():
        return False
    task = _claim()
    if task is None:
        return False
    try:
        result = _execute(task)
    except client.JiraError as exc:
        _finish(task, error=exc)
    except Exception:
        # Raw provider exceptions must never enter logs or persisted audit data.
        _finish(task, error=client.JiraError("Unexpected Jira sync failure; inspect integration settings",
                                            uncertain=task["operation"] != "pull"))
    else:
        _finish(task, result=result)
    return True
