"""Focused review regressions for worker health and alert lifecycle locking."""
from contextlib import contextmanager
import signal
import sys

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session
from sqlalchemy.dialects import postgresql

from app.automation import service, worker as automation_worker
from app.db import SessionLocal
from app.jira_sync import service as jira_service
from app.models import _utcnow
from app.automation.models import AutomationPolicy
from test_automation import project, finding, policy


def test_missing_database_or_schema_is_not_reported_as_completed_work(monkeypatch):
    class Unavailable:
        @staticmethod
        @contextmanager
        def begin():
            raise RuntimeError("synthetic database unavailable")
            yield
    monkeypatch.setattr(service, "SessionLocal", Unavailable)
    with pytest.raises(RuntimeError, match="synthetic database unavailable"):
        service.process_one()


def test_worker_does_not_refresh_health_after_database_failure(monkeypatch, tmp_path):
    from app import deployment
    monkeypatch.setattr(sys, "argv", ["automation-worker", "--once"])
    monkeypatch.setattr(deployment, "validate_worker_settings", lambda _: None)
    monkeypatch.setattr(automation_worker.signal, "signal", lambda *_: None)
    heartbeat = tmp_path / "heartbeat"
    monkeypatch.setattr(automation_worker, "HEARTBEAT", heartbeat)
    def fail():
        raise RuntimeError("synthetic database unavailable")
    monkeypatch.setattr(automation_worker, "evaluate_one", fail)
    called = []
    monkeypatch.setattr(jira_service, "process_one", lambda: called.append("jira") or False)
    automation_worker.main()
    assert called == ["jira"]  # One subsystem does not starve the other.
    assert not heartbeat.exists()


def test_worker_backs_off_on_failure_even_when_other_subsystem_did_work(monkeypatch, tmp_path):
    from app import deployment
    monkeypatch.setattr(sys, "argv", ["automation-worker"])
    monkeypatch.setattr(deployment, "validate_worker_settings", lambda _: None)
    handlers = {}
    monkeypatch.setattr(automation_worker.signal, "signal", lambda kind, handler: handlers.update({kind: handler}))
    monkeypatch.setattr(automation_worker, "HEARTBEAT", tmp_path / "heartbeat")
    monkeypatch.setattr(automation_worker, "evaluate_one", lambda: True)
    def fail():
        raise RuntimeError("synthetic Jira database failure")
    monkeypatch.setattr(jira_service, "process_one", fail)
    sleeps = []
    def sleep(seconds):
        sleeps.append(seconds)
        handlers[signal.SIGTERM]()
    monkeypatch.setattr(automation_worker.time, "sleep", sleep)
    automation_worker.main()
    assert sleeps == [1]


def test_successful_idle_iteration_updates_worker_health(monkeypatch, tmp_path):
    from app import deployment
    monkeypatch.setattr(sys, "argv", ["automation-worker", "--once"])
    monkeypatch.setattr(deployment, "validate_worker_settings", lambda _: None)
    monkeypatch.setattr(automation_worker.signal, "signal", lambda *_: None)
    heartbeat = tmp_path / "heartbeat"
    monkeypatch.setattr(automation_worker, "HEARTBEAT", heartbeat)
    monkeypatch.setattr(automation_worker, "evaluate_one", lambda: False)
    monkeypatch.setattr(jira_service, "process_one", lambda: False)
    automation_worker.main()
    assert heartbeat.exists()


def test_evaluator_locks_existing_generations_against_acknowledgement(client, auth_headers):
    project(client, auth_headers)
    finding(client, auth_headers)
    policy(client, auth_headers)
    assert service.process_one()
    locked_queries = []
    def record(state):
        statement = state.statement
        if state.is_select and "operational_alerts" in str(statement):
            locked_queries.append(str(statement.compile(dialect=postgresql.dialect())))
    event.listen(Session, "do_orm_execute", record)
    try:
        with SessionLocal.begin() as db:
            service._evaluate_policy(db, db.get(AutomationPolicy, "payments"), _utcnow())
    finally:
        event.remove(Session, "do_orm_execute", record)
    assert locked_queries and all("FOR UPDATE" in query for query in locked_queries)


def test_policy_pause_locks_policy_and_alert_generations(client, auth_headers):
    project(client, auth_headers)
    finding(client, auth_headers)
    policy(client, auth_headers)
    assert service.process_one()
    policy_queries, alert_queries = [], []
    def record(state):
        if not state.is_select:
            return
        query = str(state.statement.compile(dialect=postgresql.dialect()))
        if "FROM automation_policies" in query:
            policy_queries.append(query)
        if "FROM operational_alerts" in query:
            alert_queries.append(query)
    event.listen(Session, "do_orm_execute", record)
    try:
        policy(client, auth_headers, enabled=False)
    finally:
        event.remove(Session, "do_orm_execute", record)
    assert policy_queries and all("FOR UPDATE" in query for query in policy_queries)
    assert alert_queries and all("FOR UPDATE" in query for query in alert_queries)


def test_reminder_delivery_uses_current_owner_and_contact(client, auth_headers, monkeypatch):
    import json
    import httpx
    from sqlalchemy import select
    from app.automation import slack
    from app.automation.models import OperationalAlert
    from app.models import NotificationDelivery
    project(client, auth_headers)
    finding(client, auth_headers)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.invalid/synthetic")
    policy(client, auth_headers, notify_slack=True)
    assert service.process_one()
    with SessionLocal.begin() as db:
        payload = json.loads(db.scalar(select(NotificationDelivery)).payload)
        alert = db.scalar(select(OperationalAlert))
        alert.owner, alert.escalation_contact = "current-owner", "current-contact"
        alert.message = "Current assignment details"
    calls = []
    real_client = httpx.Client
    def respond(request):
        calls.append(json.loads(request.content))
        return httpx.Response(200)
    monkeypatch.setattr(slack.httpx, "Client", lambda **kwargs: real_client(
        transport=httpx.MockTransport(respond), **kwargs))
    assert slack.send_alert(payload)["ok"]
    body = json.dumps(calls)
    assert "current-owner" in body and "current-contact" in body
    assert "Current assignment details" in body


def test_mismatched_notification_metadata_is_cancelled(client, auth_headers, monkeypatch):
    import json
    from sqlalchemy import select
    from app.automation import slack
    from app.models import NotificationDelivery
    project(client, auth_headers)
    finding(client, auth_headers)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.invalid/synthetic")
    policy(client, auth_headers, notify_slack=True)
    assert service.process_one()
    with SessionLocal() as db:
        payload = json.loads(db.scalar(select(NotificationDelivery)).payload)
    monkeypatch.setattr(slack.httpx, "Client", lambda **_: pytest.fail("mismatched metadata must not be sent"))
    for field, value in (("project", "another-project"), ("resource_id", "another-finding"), ("kind", "coverage")):
        assert slack.send_alert({**payload, field: value}) == {"ok": True, "cancelled": True}
