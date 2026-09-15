"""Operational alerts use synthetic local data; never contact notification services."""
from datetime import timedelta
import json

import pytest
from sqlalchemy import func, select

from app.automation import service
from app.automation.models import AutomationPolicy, OperationalAlert
from app.db import SessionLocal
from app.models import Finding, ImportRun, NotificationDelivery, _utcnow
from app.notifications import worker

ORIGIN = "http://localhost:5000"


@pytest.fixture(autouse=True)
def settings(monkeypatch):
    monkeypatch.setenv("DASHBOARD_ORIGINS", ORIGIN)
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")


def project(client, headers, name="payments"):
    result = client.post("/catalog/projects", headers=headers, json={"name": name})
    assert result.status_code == 201, result.text


def finding(client, headers, *, name="payments", title="Synthetic finding", due=None):
    result = client.post("/ingest/signal", headers=headers, json={
        "project": name, "tool": "generic", "asset": "test.invalid", "severity": "high", "title": title,
    })
    assert result.status_code == 200, result.text
    identifier = result.json()["finding_id"]
    with SessionLocal.begin() as db:
        db.get(Finding, identifier).remediation_due_at = due or _utcnow() + timedelta(hours=12)
    return identifier


def policy(client, headers, name="payments", **changes):
    result = client.put("/automation/policies", params={"project": name}, headers=headers,
                        json={"enabled": True, "notify_slack": False, **changes})
    assert result.status_code == 200, result.text
    return result.json()["policy"]


def evaluate(client, headers, name="payments"):
    result = client.post("/automation/evaluate", params={"project": name}, headers=headers)
    assert result.status_code == 200, result.text
    assert service.process_one()


def alerts(client, headers, **params):
    return client.get("/automation/alerts", headers=headers, params=params).json()["results"]


def test_policies_are_opt_in_and_deadline_conditions_do_not_modify_findings(client, auth_headers):
    project(client, auth_headers)
    identifier = finding(client, auth_headers)
    assert not service.process_one()
    assert not alerts(client, auth_headers)
    policy(client, auth_headers)
    assert service.process_one()
    rows = alerts(client, auth_headers)
    assert len(rows) == 1 and rows[0]["condition"] == "due_soon"
    assert rows[0]["resource_id"] == identifier and rows[0]["state"] == "open"
    assert client.get(f"/findings/{identifier}", headers=auth_headers).json()["status"] == "open"
    with SessionLocal.begin() as db:
        db.get(Finding, identifier).remediation_due_at = _utcnow() - timedelta(minutes=1)
    evaluate(client, auth_headers)
    assert alerts(client, auth_headers)[0]["condition"] == "overdue"


def test_acknowledgement_reminders_escalation_and_recovery_are_deduplicated(client, auth_headers, monkeypatch):
    project(client, auth_headers)
    identifier = finding(client, auth_headers)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.invalid/synthetic")
    policy(client, auth_headers, notify_slack=True)
    service.process_one()
    row = alerts(client, auth_headers)[0]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(NotificationDelivery)) == 1
    evaluate(client, auth_headers)
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(NotificationDelivery)) == 1
    result = client.post(f"/automation/alerts/{row['id']}/acknowledge", headers=auth_headers)
    assert result.status_code == 200 and result.json()["alert"]["state"] == "acknowledged"
    assert worker.process_one()  # Suppressed before any external network call.
    with SessionLocal.begin() as db:
        assert db.scalar(select(NotificationDelivery)).status == "cancelled"
        db.get(OperationalAlert, row["id"]).last_notified_at = _utcnow() - timedelta(days=2)
    evaluate(client, auth_headers)
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(NotificationDelivery)) == 1
    # A genuinely worse condition resets acknowledgement and creates one event.
    with SessionLocal.begin() as db:
        db.get(Finding, identifier).remediation_due_at = _utcnow() - timedelta(minutes=1)
    evaluate(client, auth_headers)
    updated = alerts(client, auth_headers)[0]
    assert updated["state"] == "open" and updated["acknowledged_by"] is None
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(NotificationDelivery)) == 2
    # Risk acceptance clears alerting, but does not change the technical finding.
    with SessionLocal.begin() as db:
        db.get(Finding, identifier).risk_accepted_until = _utcnow() + timedelta(days=1)
    evaluate(client, auth_headers)
    assert not alerts(client, auth_headers)
    assert alerts(client, auth_headers, state="resolved")[0]["resolved_at"]
    with SessionLocal.begin() as db:
        db.get(Finding, identifier).risk_accepted_until = _utcnow() - timedelta(minutes=1)
    evaluate(client, auth_headers)
    assert alerts(client, auth_headers)[0]["state"] == "open"
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(NotificationDelivery)) == 3


def test_required_coverage_alerts_clear_on_report_and_reopen_on_failure(client, auth_headers):
    project(client, auth_headers)
    policy(client, auth_headers)
    for source, required in (("semgrep", True), ("optional", False)):
        result = client.post("/coverage", headers=auth_headers, json={
            "project": "payments", "source_type": "scanner", "source": source, "required": required,
        })
        assert result.status_code == 201
    service.process_one()
    rows = alerts(client, auth_headers)
    assert len(rows) == 1 and rows[0]["condition"] == "missing"
    now = _utcnow()
    with SessionLocal.begin() as db:
        db.add(ImportRun(parser="semgrep", project="payments", actor="test", content_sha256="a" * 64,
                         status="completed", imported=0, created_at=now - timedelta(minutes=2), completed_at=now))
    evaluate(client, auth_headers)
    assert not alerts(client, auth_headers)
    with SessionLocal.begin() as db:
        db.add(ImportRun(parser="semgrep", project="payments", actor="test", content_sha256="b" * 64,
                         status="failed", created_at=now + timedelta(seconds=1), completed_at=now + timedelta(seconds=2)))
    evaluate(client, auth_headers)
    assert alerts(client, auth_headers)[0]["condition"] == "failing"


def test_policy_pause_cancels_pending_delivery(client, auth_headers, monkeypatch):
    project(client, auth_headers)
    finding(client, auth_headers)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.invalid/synthetic")
    policy(client, auth_headers, notify_slack=True)
    service.process_one()
    policy(client, auth_headers, enabled=False)
    assert not alerts(client, auth_headers)
    assert worker.process_one()
    assert client.get("/notifications", headers=auth_headers, params={"status": "cancelled"}).json()["count"] == 1
    assert client.post("/automation/evaluate", headers=auth_headers,
                       params={"project": "payments"}).status_code == 409


def test_failed_or_truncated_evaluation_retains_existing_alerts(client, auth_headers, monkeypatch):
    project(client, auth_headers)
    finding(client, auth_headers)
    policy(client, auth_headers)
    service.process_one()
    before = alerts(client, auth_headers)
    monkeypatch.setattr(service, "MAX_FINDINGS", 0)
    evaluate(client, auth_headers)
    assert alerts(client, auth_headers) == before
    status = client.get("/automation", headers=auth_headers).json()["policies"][0]
    assert "limit" in status["last_error"]


def test_alerts_and_policy_reads_are_scoped_and_writes_role_checked(client, auth_headers):
    for name in ("payments", "secret/project"):
        project(client, auth_headers, name)
        finding(client, auth_headers, name=name)
        policy(client, auth_headers, name)
        service.process_one()
    all_rows = alerts(client, auth_headers)
    hidden = next(row for row in all_rows if row["project"] == "secret/project")
    visible = next(row for row in all_rows if row["project"] == "payments")
    for role in ("viewer", "analyst"):
        result = client.post("/users", headers=auth_headers, json={
            "username": role, "password": "synthetic-automation-password-123", "role": role,
            "projects": ["payments"],
        })
        assert result.status_code == 201
    result = client.post("/auth/login", headers={"Origin": ORIGIN}, json={
        "username": "viewer", "password": "synthetic-automation-password-123",
    })
    assert result.status_code == 200
    headers = {"Origin": ORIGIN}
    assert [row["project"] for row in alerts(client, headers)] == ["payments"]
    assert alerts(client, headers, project="secret/project") == []
    assert [row["project"] for row in client.get("/automation").json()["policies"]] == ["payments"]
    assert client.post(f"/automation/alerts/{visible['id']}/acknowledge", headers=headers).status_code == 403
    assert client.put("/automation/policies", params={"project": "payments"}, headers=headers,
                      json={"enabled": True}).status_code == 403
    assert client.post("/auth/login", headers=headers, json={
        "username": "analyst", "password": "synthetic-automation-password-123",
    }).status_code == 200
    assert client.post(f"/automation/alerts/{hidden['id']}/acknowledge", headers=headers).status_code == 404
    assert client.post(f"/automation/alerts/{visible['id']}/acknowledge", headers=headers).status_code == 200


def test_alert_delivery_is_plain_text_and_excludes_raw_evidence(client, auth_headers, monkeypatch):
    project(client, auth_headers)
    identifier = finding(client, auth_headers, title="<@everyone> synthetic *title*")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.invalid/synthetic")
    policy(client, auth_headers, notify_slack=True)
    service.process_one()
    with SessionLocal() as db:
        queued = db.scalar(select(NotificationDelivery))
        payload = json.loads(queued.payload)
        assert payload["resource_id"] == identifier and "description" not in payload
    import httpx
    from app.automation import slack
    calls = []
    real_client = httpx.Client

    def respond(request):
        calls.append(json.loads(request.content))
        return httpx.Response(200)

    monkeypatch.setattr(slack.httpx, "Client", lambda **kw: real_client(
        transport=httpx.MockTransport(respond), **kw))
    assert worker.process_one()
    assert len(calls) == 1 and calls[0]["mrkdwn"] is False
    assert all(block["text"]["type"] == "plain_text" for block in calls[0]["blocks"])


def test_invalid_policy_and_unknown_project_are_rejected(client, auth_headers, ingest_headers):
    assert client.put("/automation/policies", headers=auth_headers, params={"project": "unknown"},
                      json={"enabled": True}).status_code == 422
    project(client, auth_headers)
    for change in ({"warn_before_hours": 0}, {"reminder_hours": 169}, {"unexpected": True}):
        assert client.put("/automation/policies", headers=auth_headers, params={"project": "payments"},
                          json=change).status_code == 422
    assert client.get("/automation/alerts", headers=ingest_headers).status_code == 401


def test_repeat_open_alert_reminder_is_queued_once_per_interval(client, auth_headers, monkeypatch):
    project(client, auth_headers)
    finding(client, auth_headers)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.invalid/synthetic")
    policy(client, auth_headers, notify_slack=True, reminder_hours=1)
    service.process_one()
    with SessionLocal.begin() as db:
        db.scalar(select(OperationalAlert)).last_notified_at = _utcnow() - timedelta(hours=2)
    evaluate(client, auth_headers)
    evaluate(client, auth_headers)
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(NotificationDelivery)) == 2
