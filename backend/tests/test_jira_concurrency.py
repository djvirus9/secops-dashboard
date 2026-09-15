"""Local queue/claim fencing and bounded, current-tenant link discovery."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event
from uuid import uuid4

import pytest
from sqlalchemy import event, select

from app.db import SessionLocal, engine
from app.jira_sync import routes, service
from app.jira_sync.models import JiraIssueLink, JiraSyncControl
from app.models import NotificationDelivery, _utcnow
from test_jira_progress import configured, seed, remote


@pytest.mark.parametrize("operation", ["pull", "push_status"])
def test_claim_waits_for_queue_transaction_and_retains_the_approved_operation(client, auth_headers, monkeypatch, operation):
    finding_id = seed(status="investigating")
    baseline = remote()
    with SessionLocal.begin() as db:
        row = db.get(JiraIssueLink, finding_id)
        row.remote_status_id, row.remote_status_category = baseline["status_id"], baseline["category"]
        row.remote_updated_at, row.last_synced_at = baseline["updated_at"], _utcnow()
    queue_read, claim_started = Event(), Event()
    original_queue_link, original_lock = routes._queue_link, service._lock_accounts

    def hold_queue(db, finding, config):
        row = original_queue_link(db, finding, config)
        queue_read.set()
        # Let the worker try to claim after the API has read the previous idle
        # state. Its lifecycle lock must wait until this queue transaction ends.
        assert claim_started.wait(5)
        return row

    def claim_lock(db):
        claim_started.set()
        return original_lock(db)

    monkeypatch.setattr(routes, "_queue_link", hold_queue)
    monkeypatch.setattr(service, "_lock_accounts", claim_lock)

    def queue():
        if operation == "pull":
            return client.post(f"/findings/{finding_id}/jira/pull", headers=auth_headers)
        return client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers, json={
            "field": "status", "expected_local_status": "investigating",
            "expected_local_assignee": None, "expected_remote_updated_at": baseline["updated_at"],
        })

    with ThreadPoolExecutor(max_workers=2) as pool:
        queued = pool.submit(queue)
        assert queue_read.wait(5)
        claimed = pool.submit(service._claim)
        response, task = queued.result(timeout=10), claimed.result(timeout=10)
    assert response.status_code == 202, response.text
    assert task is not None and task["operation"] == operation
    with SessionLocal() as db:
        row, control = db.get(JiraIssueLink, finding_id), db.get(JiraSyncControl, 1)
        assert row.status == "syncing" and row.operation == operation
        assert row.claim_token == task["token"] == control.claim_token
        if operation == "push_status":
            assert task["pending"]["category"] == "indeterminate"


def test_current_claim_always_acquires_lifecycle_gate_then_finding_then_link(monkeypatch):
    finding_id = seed()
    task = service._claim()
    seen = []
    original_lock = service._lock_accounts

    def lock(db):
        seen.append("lifecycle")
        return original_lock(db)

    def record(conn, cursor, statement, parameters, context, executemany):
        statement = statement.strip().lower()
        if statement.startswith("update findings "):
            seen.append("finding")
        if statement.startswith("update jira_issue_links "):
            seen.append("link")

    monkeypatch.setattr(service, "_lock_accounts", lock)
    event.listen(engine, "before_cursor_execute", record)
    try:
        with SessionLocal.begin() as db:
            row, finding = service._current_claim(db, task)
            assert row.finding_id == finding.id == finding_id
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert seen == ["lifecycle", "finding", "link"]


def test_two_workers_cannot_claim_the_same_operation():
    finding_id = seed()
    start = Barrier(2)

    def claim():
        start.wait(timeout=5)
        return service._claim()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: claim(), range(2)))
    tasks = [task for task in results if task is not None]
    assert len(tasks) == 1 and tasks[0]["finding_id"] == finding_id


def test_api_cannot_replace_claimed_work_with_a_new_pull_or_push(client, auth_headers):
    finding_id = seed()
    task = service._claim()
    assert client.post(f"/findings/{finding_id}/jira/pull", headers=auth_headers).status_code == 409
    assert client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers, json={
        "field": "status", "expected_local_status": "open", "expected_local_assignee": None,
        "expected_remote_updated_at": "synthetic-baseline",
    }).status_code == 409
    with SessionLocal() as db:
        row = db.get(JiraIssueLink, finding_id)
        assert row.status == "syncing" and row.claim_token == task["token"] and row.operation == "pull"


@pytest.mark.parametrize("invalid", ["other_tenant", "bad-key", "SEC-0", "SEC-1\n", "SEC-1?query", "ÄBC-1"])
def test_older_invalid_deliveries_cannot_starve_current_tenant_discovery(invalid):
    for index in range(24):
        finding_id = seed(link=False)
        with SessionLocal.begin() as db:
            delivery = db.scalar(select(NotificationDelivery).where(NotificationDelivery.finding_id == finding_id))
            delivery.created_at = _utcnow() - timedelta(days=2, seconds=index)
            if invalid == "other_tenant":
                delivery.external_url = "https://previous.atlassian.net/browse/SEC-1"
            else:
                delivery.external_id = invalid
                delivery.external_url = "https://synthetic.atlassian.net/browse/" + invalid
    current = seed(link=False)
    task = service._claim()
    assert task is not None and task["finding_id"] == current
    with SessionLocal() as db:
        assert len(db.scalars(select(JiraIssueLink)).all()) == 1


def test_later_current_tenant_delivery_can_link_despite_older_unusable_evidence():
    finding_id = seed(link=False)
    with SessionLocal.begin() as db:
        old = db.scalar(select(NotificationDelivery).where(NotificationDelivery.finding_id == finding_id))
        old.created_at = _utcnow() - timedelta(days=1)
        old.external_url = "https://previous.atlassian.net/browse/SEC-1"
        db.add(NotificationDelivery(event_key=str(uuid4()), finding_id=finding_id, channel="jira",
                                    status="sent", payload="{}", external_id="SEC-2",
                                    external_url="https://synthetic.atlassian.net/browse/SEC-2"))
    task = service._claim()
    assert task is not None and task["finding_id"] == finding_id and task["issue_key"] == "SEC-2"


def test_discovery_remains_bounded_to_twenty_distinct_findings_per_tick():
    ids = [seed(link=False) for _ in range(23)]
    task = service._claim()
    assert task is not None and task["finding_id"] in ids
    with SessionLocal() as db:
        assert len(db.scalars(select(JiraIssueLink)).all()) == 20
