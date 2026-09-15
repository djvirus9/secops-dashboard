"""Plain-text operational alerts sent through the configured trusted-team channel."""
import os

import httpx

from ..db import SessionLocal
from .models import AutomationPolicy, OperationalAlert


def send_alert(payload):
    # Recheck immediately before delivery: an old retry must not re-notify after
    # acknowledgement, recovery, policy pause, or a newer alert generation.
    with SessionLocal() as db:
        row = db.get(OperationalAlert, payload["alert_id"])
        policy = db.get(AutomationPolicy, payload["project"])
        if (row is None or row.state != "open" or row.generation != payload["generation"]
                or row.project != payload["project"] or row.kind != payload["kind"]
                or row.resource_id != payload["resource_id"]
                or not policy or not policy.enabled or not policy.notify_slack):
            return {"ok": True, "cancelled": True}
        # A retry may outlive an ownership or contact update without changing
        # the alert generation. Route the reminder using current persisted
        # display metadata, not the superseded outbox snapshot.
        payload = {**payload, **{name: getattr(row, name) for name in (
            "title", "message", "owner", "team", "escalation_contact",
        )}}
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook:
        return {"ok": False, "error": "Slack is not configured", "retryable": False}
    lines = [payload["title"], f"Project: {payload['project']}",
             f"Owner: {payload.get('owner') or 'unassigned'}; Team: {payload.get('team') or 'unassigned'}",
             f"Escalation contact: {payload.get('escalation_contact') or 'not configured'}",
             payload["message"], f"Alert ID: {payload['alert_id']}"]
    body = {"text": payload["title"][:300], "mrkdwn": False, "blocks": [
        {"type": "section", "text": {"type": "plain_text", "text": line[:2900]}}
        for line in lines
    ]}
    try:
        with httpx.Client(timeout=10.0, follow_redirects=False) as client:
            response = client.post(webhook, json=body)
        return {"ok": response.status_code == 200,
                "retryable": response.status_code == 429 or response.status_code >= 500,
                "error": f"Slack returned HTTP {response.status_code}"}
    except httpx.HTTPError:
        return {"ok": False, "error": "Slack connection failed", "retryable": True}
