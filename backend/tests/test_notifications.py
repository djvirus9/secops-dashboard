import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import httpx
from sqlalchemy import select, update

from app.db import SessionLocal
from app.models import NotificationDelivery
from app.notifications import jira, slack, worker
from app.notifications.outbox import enqueue, utcnow


def queued(channel="slack"):
    with SessionLocal.begin() as db:
        return enqueue(db, event_key=f"{channel}:test", channel=channel, payload={
            "title": "Synthetic <@everyone>", "severity": "high", "asset": "host", "risk_score": 100,
            "finding_id": "synthetic", "tool": "test", "is_new": True, "occurrences": 1,
            "description": "Normalized evidence", "recommendation": "Upgrade the package",
        })


def delivery(identifier):
    with SessionLocal() as db:
        row = db.get(NotificationDelivery, identifier)
        return {"status": row.status, "attempts": row.attempts, "external_id": row.external_id,
                "next_attempt_at": row.next_attempt_at, "last_error": row.last_error}


def test_notifications_survive_request_transaction_and_retry_transient_failure(monkeypatch):
    identifier = queued()
    monkeypatch.setattr(worker, "deliver", lambda task: {"ok": False, "retryable": True, "error": "HTTP 429"})
    assert worker.process_one()
    row = delivery(identifier)
    assert row["status"] == "pending" and row["attempts"] == 1
    assert row["next_attempt_at"] > utcnow()
    assert worker.process_one() is False
    with SessionLocal.begin() as db:
        db.execute(update(NotificationDelivery).values(next_attempt_at=utcnow() - timedelta(seconds=1)))
    monkeypatch.setattr(worker, "deliver", lambda task: {"ok": True})
    assert worker.process_one()
    assert delivery(identifier)["status"] == "sent"
    assert worker.process_one() is False


def test_uncertain_jira_delivery_requires_explicit_review(client, auth_headers, monkeypatch):
    identifier = queued("jira")
    monkeypatch.setattr(worker, "deliver", lambda task: {"ok": False, "unknown_outcome": True})
    assert worker.process_one()
    assert delivery(identifier)["status"] == "needs_review"
    assert worker.process_one() is False
    assert client.post(f"/notifications/{identifier}/retry", headers=auth_headers, json={}).status_code == 409
    assert client.post(f"/notifications/{identifier}/retry", headers=auth_headers,
                       json={"confirmed_no_issue": True}).status_code == 200
    monkeypatch.setattr(worker, "deliver", lambda task: {"ok": True, "issue_key": "SEC-42", "url": "https://jira.invalid/browse/SEC-42"})
    assert worker.process_one()
    assert delivery(identifier)["external_id"] == "SEC-42"
    assert client.post(f"/notifications/{identifier}/retry", headers=auth_headers, json={}).status_code == 409


def test_concurrent_workers_cannot_claim_same_delivery():
    identifier = queued()
    with ThreadPoolExecutor(max_workers=4) as pool:
        tasks = list(pool.map(lambda _: worker.claim_delivery(), range(4)))
    claims = [task for task in tasks if task]
    assert len(claims) == 1 and claims[0]["id"] == identifier
    assert delivery(identifier)["attempts"] == 1


def test_crashed_jira_lease_is_held_for_review():
    identifier = queued("jira")
    assert worker.claim_delivery()
    with SessionLocal.begin() as db:
        db.execute(update(NotificationDelivery).values(updated_at=utcnow() - timedelta(seconds=worker.LEASE_SECONDS + 1)))
    assert worker.claim_delivery() is None
    assert delivery(identifier)["status"] == "needs_review"


def test_retry_exhaustion_is_visible_and_manual_retry_allowed(client, auth_headers, monkeypatch):
    identifier = queued()
    monkeypatch.setenv("NOTIFICATION_MAX_ATTEMPTS", "1")
    monkeypatch.setattr(worker, "deliver", lambda task: {"ok": False, "retryable": True, "error": "HTTP 503"})
    assert worker.process_one()
    assert delivery(identifier)["status"] == "failed"
    history = client.get("/notifications?status=failed", headers=auth_headers).json()
    assert history["count"] == 1 and history["results"][0]["last_error"] == "HTTP 503"
    assert client.post(f"/notifications/{identifier}/retry", headers=auth_headers, json={}).status_code == 200


def test_unexpected_errors_do_not_expose_credentials(monkeypatch):
    identifier = queued("jira")
    def broken(task):
        raise RuntimeError("sensitive-api-token")
    monkeypatch.setattr(worker, "deliver", broken)
    worker.process_one()
    assert delivery(identifier)["status"] == "needs_review"
    assert "sensitive-api-token" not in delivery(identifier)["last_error"]


def test_jira_uses_adf_and_retains_external_issue_key(monkeypatch):
    for key, value in {"JIRA_BASE_URL": "https://jira.invalid", "JIRA_EMAIL": "review@invalid",
                       "JIRA_API_TOKEN": "synthetic-token", "JIRA_PROJECT_KEY": "SEC"}.items():
        monkeypatch.setenv(key, value)
    requests = []
    def handle(request):
        requests.append(request)
        return httpx.Response(201, json={"key": "SEC-42", "id": "42"})
    real_client = httpx.Client
    monkeypatch.setattr(jira.httpx, "Client", lambda **kwargs: real_client(transport=httpx.MockTransport(handle), **kwargs))
    result = jira.create_jira_issue_sync(title="Test", severity="high", asset="host", risk_score=100,
                                        finding_id="synthetic", tool="test", description="Evidence", recommendation="Fix")
    fields = json.loads(requests[0].content)["fields"]
    assert fields["description"]["type"] == "doc" and fields["description"]["version"] == 1
    text = json.dumps(fields["description"])
    assert "Evidence" in text and "Fix" in text
    assert "priority" not in fields  # Projects can have custom priority schemes.
    assert result["issue_key"] == "SEC-42"


def test_slack_scanner_fields_do_not_interpret_mentions(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://slack.invalid/webhook")
    sent = []
    def handle(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, text="ok")
    real_client = httpx.Client
    monkeypatch.setattr(slack.httpx, "Client", lambda **kwargs: real_client(transport=httpx.MockTransport(handle), **kwargs))
    result = slack.send_slack_notification_sync(title="<!channel>", severity="high", asset="<@U123>",
                                               risk_score=100, finding_id="synthetic", tool="test")
    assert result["ok"]
    assert sent[0]["mrkdwn"] is False
    assert all(field["type"] == "plain_text" for field in sent[0]["attachments"][0]["blocks"][1]["fields"])
