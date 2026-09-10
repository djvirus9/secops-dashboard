"""Run with python -m app.notifications.worker. Delivery intents survive restarts.

Claims are leased and fenced. Uncertain Jira POSTs require operator review;
Slack delivery is at least once after a worker crash.
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import time
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from sqlalchemy import and_, or_, select, update

from ..db import SessionLocal
from ..limits import positive_int_setting
from ..models import ImportRun, NotificationDelivery
from .jira import create_jira_issue_sync
from .outbox import configured_channels, utcnow
from .slack import send_slack_notification_sync

logger = logging.getLogger(__name__)
HEARTBEAT = Path("/tmp/secops-worker-heartbeat")
LEASE_SECONDS = 120


def claim_delivery() -> dict | None:
    now = utcnow()
    expired = now - timedelta(seconds=LEASE_SECONDS)
    with SessionLocal.begin() as db:
        db.execute(update(ImportRun).where(
            ImportRun.status == "processing",
            ImportRun.created_at < now - timedelta(seconds=positive_int_setting("IMPORT_TIMEOUT_SECONDS", 900)),
        ).values(status="interrupted", completed_at=now,
                 error="Import expired or was interrupted; submit the report again"))
        db.execute(update(NotificationDelivery).where(
            NotificationDelivery.channel == "jira",
            NotificationDelivery.status == "processing",
            NotificationDelivery.updated_at < expired,
        ).values(status="needs_review", claim_token=None, updated_at=now,
                 last_error="Worker interrupted; check Jira for an existing issue before retrying"))
        eligible = or_(
            and_(NotificationDelivery.status == "pending", NotificationDelivery.next_attempt_at <= now),
            and_(NotificationDelivery.channel == "slack", NotificationDelivery.status == "processing",
                 NotificationDelivery.updated_at < expired),
        )
        candidate = db.scalar(select(NotificationDelivery.id).where(eligible)
                              .order_by(NotificationDelivery.next_attempt_at, NotificationDelivery.id).limit(1))
        if not candidate:
            return None
        token = str(uuid4())
        row = db.execute(update(NotificationDelivery).where(
            NotificationDelivery.id == candidate, eligible,
        ).values(status="processing", claim_token=token, updated_at=now,
                 attempts=NotificationDelivery.attempts + 1)
            .returning(NotificationDelivery.id, NotificationDelivery.channel,
                       NotificationDelivery.payload, NotificationDelivery.attempts)).mappings().first()
        return {**row, "claim_token": token} if row else None


def deliver(task: dict) -> dict:
    if task["channel"] not in configured_channels():
        return {"ok": False, "error": "Integration is not configured", "retryable": False}
    payload = json.loads(task["payload"])
    common = {key: payload[key] for key in ("title", "severity", "asset", "risk_score", "finding_id", "tool")}
    if task["channel"] == "slack":
        return send_slack_notification_sync(**common, is_new=payload["is_new"], occurrences=payload["occurrences"])
    return create_jira_issue_sync(**common, description=payload.get("description", ""),
                                  recommendation=payload.get("recommendation", ""),
                                  project=payload.get("project", ""), component=payload.get("component", ""),
                                  component_version=payload.get("component_version", ""))


def process_one() -> bool:
    task = claim_delivery()
    if task is None:
        return False
    try:
        result = deliver(task) or {"ok": False, "error": "Integration is not configured", "retryable": False}
    except Exception:
        logger.error("Notification %s failed unexpectedly", task["id"])
        result = {"ok": False, "error": "Unexpected delivery failure",
                  "unknown_outcome": task["channel"] == "jira"}
    now = utcnow()
    values = {"updated_at": now, "claim_token": None}
    if result.get("ok"):
        values.update(status="sent", last_error=None,
                      external_id=result.get("issue_key"), external_url=result.get("url"))
    elif result.get("unknown_outcome"):
        values.update(status="needs_review", last_error="Delivery outcome unknown; check Jira before retrying")
    else:
        retry = result.get("retryable", True) and task["attempts"] < positive_int_setting("NOTIFICATION_MAX_ATTEMPTS", 5)
        values.update(status="pending" if retry else "failed",
                      last_error=result.get("error", "Integration rejected the request")[:500],
                      next_attempt_at=now + timedelta(seconds=min(30 * 2 ** min(task["attempts"] - 1, 7), 3600)))
    with SessionLocal.begin() as db:
        db.execute(update(NotificationDelivery).where(
            NotificationDelivery.id == task["id"],
            NotificationDelivery.claim_token == task["claim_token"],
        ).values(**values))
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--health", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.health:
        max_age = max(180, positive_int_setting("NOTIFICATION_POLL_SECONDS", 5) * 3)
        raise SystemExit(0 if HEARTBEAT.exists() and time.time() - HEARTBEAT.stat().st_mtime < max_age else 1)
    from ..deployment import validate_backend_settings
    validate_backend_settings()
    logging.basicConfig(level=logging.INFO)
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        try:
            processed = process_one()
            HEARTBEAT.touch()
        except Exception:
            logger.error("Worker database operation failed")
            processed = False
        if args.once:
            break
        if not processed:
            for _ in range(positive_int_setting("NOTIFICATION_POLL_SECONDS", 5)):
                if stopping:
                    break
                time.sleep(1)


if __name__ == "__main__":
    main()
