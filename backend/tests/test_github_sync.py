"""Synthetic end-to-end sync, authorization, failure and lease regressions."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import json
from threading import Barrier

import pytest
from sqlalchemy import func, select

from app.db import SessionLocal
from app.github_sync import client as github, routes, service
from app.github_sync.models import GitHubAlert, GitHubConnection, GitHubSyncRun
from app.models import AuditEvent, Comment, Finding, ImportRun, NotificationDelivery, Signal, _utcnow


@pytest.fixture
def remote(monkeypatch):
    monkeypatch.setenv("GITHUB_SYNC_TOKEN", "synthetic-github-token-000000000000000000")
    alerts = [github.RemoteAlert(source="code_scanning", number=1, state="open", title="Synthetic CodeQL",
                                 severity="high", file_path="src/app.py", line_number=12),
              github.RemoteAlert(source="dependabot", number=1, state="fixed", title="Synthetic dependency",
                                 severity="critical", component="fixture-package", cve_id="CVE-2026-12345")]
    monkeypatch.setattr(github, "fetch_alerts", lambda repository, sources: list(alerts))
    return alerts


def create(client, auth_headers, **options):
    response = client.post("/github-sync", headers=auth_headers, json={
        "repository": "Fixture/Repository", "project": "repo-one", "sources": ["code_scanning", "dependabot"],
        **options,
    })
    assert response.status_code == 201, response.text
    return response.json()["connection"]


def queue(client, headers, connection):
    response = client.post(f"/github-sync/{connection['id']}/sync", headers=headers)
    assert response.status_code == 202, response.text


def count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def test_unconfigured_mappings_are_saved_without_network_or_secrets(client, auth_headers, monkeypatch):
    connection = create(client, auth_headers)
    monkeypatch.setattr(github, "fetch_alerts", lambda *_: pytest.fail("Unconfigured worker must not fetch"))
    assert service.process_one() is False
    listing = client.get("/github-sync", headers=auth_headers)
    assert listing.json() == {"configured": False, "count": 1, "results": [connection]}
    assert listing.headers["cache-control"] == "no-store"
    assert connection["repository"] == "fixture/repository" and connection["status"] == "queued"
    assert client.post(f"/github-sync/{connection['id']}/sync", headers=auth_headers).status_code == 503
    with SessionLocal() as db:
        assert count(db, GitHubSyncRun) == count(db, Finding) == 0


@pytest.mark.parametrize("options", [
    {"repository": "https://github.com/owner/repo"}, {"repository": "owner/.."},
    {"repository": "owner/repo%2fadmin"}, {"repository": "owner/repo?x=1"},
    {"repository": "owner/repo/other"}, {"repository": "owner\\host/repo"},
    {"repository": "öwner/repo"}, {"sources": []}, {"sources": ["dependabot", "dependabot"]},
    {"sources": ["secret_scanning"]}, {"interval_minutes": 14}, {"interval_minutes": True},
    {"project": "😀" * 129}, {"project": "bad\x00project"}, {"token": "must-not-be-accepted"},
])
def test_connection_validation(client, auth_headers, options):
    response = client.post("/github-sync", headers=auth_headers, json={
        "repository": "owner/repo", "project": "one", "sources": ["dependabot"], **options,
    })
    assert response.status_code == 422


def test_mapping_is_immutable_unique_and_bounded(client, auth_headers, monkeypatch):
    connection = create(client, auth_headers)
    assert client.post("/github-sync", headers=auth_headers, json={
        "repository": "FIXTURE/REPOSITORY", "project": "two", "sources": ["dependabot"],
    }).status_code == 409
    path = f"/github-sync/{connection['id']}"
    for payload in ({"project": "two"}, {"repository": "other/repo"}, {"sources": ["dependabot"]},
                    {"interval_minutes": 0}, {"enabled": "false"}):
        assert client.patch(path, headers=auth_headers, json=payload).status_code == 422
    monkeypatch.setattr(routes, "MAX_CONNECTIONS", 1)
    assert client.post("/github-sync", headers=auth_headers, json={
        "repository": "other/repo", "project": "two", "sources": ["dependabot"],
    }).status_code == 422


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_admin_role_and_csrf_for_every_management_operation(client, auth_headers, monkeypatch, role):
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("DASHBOARD_ORIGINS", "http://localhost:5000")
    connection = create(client, auth_headers)
    assert client.post("/users", headers=auth_headers, json={"username": "synthetic-user", "role": role,
        "password": "synthetic-password-000000", "projects": ["repo-one"]}).status_code == 201
    assert client.post("/auth/login", headers={"Origin": "http://localhost:5000"}, json={
        "username": "synthetic-user", "password": "synthetic-password-000000"}).status_code == 200
    path = f"/github-sync/{connection['id']}"
    for suffix in ("/github-sync", path + "/runs"):
        assert client.get(suffix).status_code == (200 if role == "admin" else 403)
    assert client.patch(path, json={"enabled": False}).status_code == 403
    assert client.patch(path, headers={"Origin": "https://untrusted.invalid"}, json={"enabled": False}).status_code == 403
    assert client.patch(path, headers={"Origin": "http://localhost:5000"}, json={"enabled": False}).status_code == (200 if role == "admin" else 403)
    if role != "admin":
        assert client.post(path + "/sync", headers={"Origin": "http://localhost:5000"}).status_code == 403
        assert client.post("/github-sync", headers={"Origin": "http://localhost:5000"}, json={
            "repository": "other/repo", "project": "one", "sources": ["dependabot"]}).status_code == 403


def test_scanner_cannot_manage_connections(client, auth_headers, ingest_headers):
    connection = create(client, auth_headers)
    token = client.post("/scanner-tokens", headers=auth_headers, json={"name": "Fixture", "project": "repo-one"}).json()["token"]
    for headers in (ingest_headers, {"X-API-Key": token}):
        assert client.get("/github-sync", headers=headers).status_code == 401
        assert client.post(f"/github-sync/{connection['id']}/sync", headers=headers).status_code == 401


def test_complete_snapshot_has_stable_identity_and_preserves_local_triage(client, auth_headers, remote, monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/synthetic/fixture/value")
    connection = create(client, auth_headers)
    assert service.process_one() is True
    assert service.process_one() is False  # Interval is respected.
    with SessionLocal() as db:
        finding = db.scalar(select(Finding).where(Finding.tool == "github-code-scanning"))
        finding_id = finding.id
        assert finding.project == "repo-one" and finding.status == "open"
        assert json.loads(finding.references_json) == ["https://github.com/fixture/repository/security/code-scanning/1"]
        assert db.scalar(select(Finding).where(Finding.tool == "github-dependabot")).status == "resolved"
        assert count(db, Finding) == count(db, Signal) == count(db, GitHubAlert) == 2
        assert count(db, ImportRun) == count(db, NotificationDelivery) == 1
    assert client.patch(f"/findings/{finding_id}", headers=auth_headers, json={"status": "closed", "assignee": "alice"}).status_code == 200
    previous_seen = _utcnow() - timedelta(hours=2)
    with SessionLocal.begin() as db:
        db.get(Finding, finding_id).last_seen = previous_seen
    queue(client, auth_headers, connection)
    assert service.process_one() is True
    with SessionLocal() as db:
        finding = db.get(Finding, finding_id)
        assert (finding.status, finding.assignee, finding.occurrences) == ("closed", "alice", 1)
        assert finding.last_seen > previous_seen
        assert count(db, Signal) == 2 and count(db, ImportRun) == count(db, NotificationDelivery) == 1
        last_run = db.scalar(select(GitHubSyncRun).order_by(GitHubSyncRun.started_at.desc()))
        assert (last_run.imported, last_run.new_findings, last_run.updated) == (2, 0, 0)
    remote[0] = replace(remote[0], title="Updated rule metadata")
    queue(client, auth_headers, connection)
    service.process_one()
    with SessionLocal() as db:
        finding = db.get(Finding, finding_id)
        assert finding.title == "Updated rule metadata" and finding.status == "closed" and finding.assignee == "alice"
        assert count(db, Finding) == 2 and count(db, NotificationDelivery) == 1


def test_source_transitions_close_reopen_and_missing_alerts_do_not_close(client, auth_headers, remote):
    connection = create(client, auth_headers)
    service.process_one()
    remote[0] = replace(remote[0], state="fixed")
    queue(client, auth_headers, connection)
    service.process_one()
    with SessionLocal() as db:
        assert set(db.scalars(select(Finding.status))) == {"resolved"}
        assert count(db, Comment) == 1
    remote[0] = replace(remote[0], state="open")
    queue(client, auth_headers, connection)
    service.process_one()
    remote.clear()
    queue(client, auth_headers, connection)
    service.process_one()
    with SessionLocal() as db:
        assert set(db.scalars(select(Finding.status))) == {"resolved", "open"}
        assert count(db, Finding) == count(db, GitHubAlert) == count(db, Comment) == 2


def test_failure_is_atomic_and_rate_limit_delays_retry(client, auth_headers, remote, monkeypatch):
    connection = create(client, auth_headers)
    service.process_one()
    def failed(*_):
        raise github.GitHubFetchError("GitHub rate limit reached; retry later", retry_after=7200)
    monkeypatch.setattr(github, "fetch_alerts", failed)
    queue(client, auth_headers, connection)
    service.process_one()
    with SessionLocal() as db:
        row = db.get(GitHubConnection, connection["id"])
        assert row.status == "failed" and row.last_error == "GitHub rate limit reached; retry later"
        assert row.next_sync_at > _utcnow() + timedelta(seconds=7100)
        assert count(db, Finding) == count(db, Signal) == 2 and count(db, ImportRun) == 1


def test_write_failure_rolls_back_entire_batch_and_redacts_exception(client, auth_headers, remote, monkeypatch):
    connection = create(client, auth_headers)
    original = service.enqueue_finding
    def fail_on_second(db, finding, **kwargs):
        if finding.tool == "github-dependabot":
            raise RuntimeError("sensitive-server-token-must-not-appear")
        return original(db, finding, **kwargs)
    remote[1] = replace(remote[1], state="open")
    monkeypatch.setattr(service, "enqueue_finding", fail_on_second)
    service.process_one()
    with SessionLocal() as db:
        assert count(db, Finding) == count(db, Signal) == count(db, ImportRun) == count(db, GitHubAlert) == 0
        row = db.get(GitHubConnection, connection["id"])
        assert row.status == "failed" and "sensitive" not in row.last_error


def test_pause_fences_inflight_write_and_reenable_queues_fresh_snapshot(client, auth_headers, remote):
    connection = create(client, auth_headers)
    stale = service.claim_sync()
    path = f"/github-sync/{connection['id']}"
    assert client.post(path + "/sync", headers=auth_headers).status_code == 409
    assert client.patch(path, headers=auth_headers, json={"enabled": False}).status_code == 200
    assert client.post(path + "/sync", headers=auth_headers).status_code == 409
    assert service.apply_snapshot(stale, remote) is False
    assert service.claim_sync() is None
    assert client.patch(path, headers=auth_headers, json={"enabled": True, "interval_minutes": 120}).status_code == 200
    current = service.claim_sync()
    assert service.apply_snapshot(stale, remote) is False
    assert service.apply_snapshot(current, remote) is True
    with SessionLocal() as db:
        assert db.get(GitHubSyncRun, stale["claim_token"]).status == "cancelled"
        assert db.get(GitHubConnection, connection["id"]).interval_minutes == 120
        assert count(db, Finding) == 2


def test_expired_lease_is_recovered_and_old_worker_cannot_commit(client, auth_headers, remote):
    connection = create(client, auth_headers)
    stale = service.claim_sync()
    with SessionLocal.begin() as db:
        db.get(GitHubConnection, connection["id"]).claimed_at = _utcnow() - timedelta(seconds=service.LEASE_SECONDS + 1)
    assert service.apply_snapshot(stale, remote) is False
    fresh = service.claim_sync()
    assert fresh["claim_token"] != stale["claim_token"]
    service.fail_sync(stale, "Old worker failure")
    assert service.apply_snapshot(fresh, remote) is True
    with SessionLocal() as db:
        assert db.get(GitHubSyncRun, stale["claim_token"]).status == "interrupted"
        assert db.get(GitHubConnection, connection["id"]).last_error is None


def test_concurrent_workers_claim_a_connection_once(client, auth_headers, remote):
    create(client, auth_headers)
    barrier = Barrier(2)
    def claim():
        barrier.wait()
        return service.claim_sync()
    with ThreadPoolExecutor(max_workers=2) as pool:
        tasks = list(pool.map(lambda _: claim(), range(2)))
    assert sum(task is not None for task in tasks) == 1
    with SessionLocal() as db:
        assert count(db, GitHubSyncRun) == 1


def test_synced_findings_and_history_obey_existing_project_permissions(client, auth_headers, remote, monkeypatch):
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("DASHBOARD_ORIGINS", "http://localhost:5000")
    create(client, auth_headers)
    service.process_one()
    assert client.post("/users", headers=auth_headers, json={"username": "viewer", "password": "synthetic-password-000000",
        "role": "viewer", "projects": ["different-project"]}).status_code == 201
    assert client.post("/auth/login", headers={"Origin": "http://localhost:5000"}, json={
        "username": "viewer", "password": "synthetic-password-000000"}).status_code == 200
    for path in ("/findings", "/assets", "/imports"):
        assert client.get(path).json()["count"] == 0
    assert client.get("/github-sync").status_code == 403
    with SessionLocal() as db:
        events = db.scalars(select(AuditEvent).where(AuditEvent.action.like("github_sync.%"))).all()
        assert events and all("synthetic-github-token" not in row.details_json for row in events)
