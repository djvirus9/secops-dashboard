"""Project scope, approval, identity mapping and Jira reconciliation regressions."""
import json
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select, update

from app.db import SessionLocal
from app.jira_sync import client as jira, service
from app.jira_sync.models import JiraIssueLink, JiraSyncControl, JiraUserMapping
from app.models import AuditEvent, Comment, Finding, NotificationDelivery, User, _utcnow


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setenv("JIRA_SYNC_ENABLED", "true")
    monkeypatch.setenv("JIRA_BASE_URL", "https://synthetic.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "synthetic@example.invalid")
    monkeypatch.setenv("JIRA_API_TOKEN", "synthetic-only-not-a-real-token")


def seed(*, status="open", assignee=None, project="payments", link=True):
    with SessionLocal.begin() as db:
        finding = Finding(fingerprint=uuid4().hex, tool="synthetic", project=project,
                          title="Synthetic finding", severity="high", asset="api.example.invalid",
                          signal_id=str(uuid4()), status=status, assignee=assignee)
        db.add(finding)
        db.flush()
        db.add(NotificationDelivery(event_key=f"jira:{finding.id}", finding_id=finding.id, channel="jira",
                                   status="sent", payload="{}", external_id="SEC-1",
                                   external_url="https://synthetic.atlassian.net/browse/SEC-1"))
        if link:
            db.add(JiraIssueLink(finding_id=finding.id, issue_key="SEC-1", base_url="https://synthetic.atlassian.net"))
        return finding.id


def user(username="analyst", project="payments", *, role="analyst", active=True):
    with SessionLocal.begin() as db:
        row = User(username=username, password_hash="synthetic-unused", role=role,
                   projects_json=json.dumps([project]), active=active)
        db.add(row)
        db.flush()
        return row.id


def remote(category="new", status_id="100", owner=None, revision=1):
    return {"status_id": status_id, "status": {"new": "To Do", "done": "Done", "indeterminate": "In Progress"}[category],
            "category": category, "assignee_id": owner, "assignee": "Remote analyst" if owner else None,
            "updated_at": f"2026-09-16T10:00:{revision:02d}.000+0000"}


def make_due(finding_id):
    with SessionLocal.begin() as db:
        db.execute(update(JiraSyncControl).values(next_request_at=_utcnow() - timedelta(seconds=1)))
        db.execute(update(JiraIssueLink).where(JiraIssueLink.finding_id == finding_id)
                   .values(next_sync_at=_utcnow() - timedelta(seconds=1)))


def pull(monkeypatch, finding_id, value):
    monkeypatch.setattr(jira.JiraClient, "issue", lambda self, key: value)
    make_due(finding_id)
    assert service.process_one()


def read(finding_id):
    with SessionLocal() as db:
        finding, link = db.get(Finding, finding_id), db.get(JiraIssueLink, finding_id)
        return {"status": finding.status, "assignee": finding.assignee, "verified_at": finding.verified_at,
                "verification_requested_at": finding.verification_requested_at, "link_status": link.status,
                "remote_status": link.remote_status, "error": link.last_error, "next_sync_at": link.next_sync_at}


def test_disabled_sync_performs_no_network(monkeypatch):
    seed()
    monkeypatch.setenv("JIRA_SYNC_ENABLED", "false")
    monkeypatch.setattr(jira.JiraClient, "issue", lambda *_: pytest.fail("unexpected network"))
    assert not service.process_one()


def test_successful_delivery_link_discovery_and_first_done_is_only_baseline(monkeypatch):
    finding_id = seed(link=False)
    pull(monkeypatch, finding_id, remote("done", "200"))
    result = read(finding_id)
    assert result["status"] == "open" and result["remote_status"] == "Done"
    assert result["verification_requested_at"] is None


def test_actual_done_transition_requests_verification_and_unchanged_done_never_reapplies(monkeypatch):
    finding_id = seed()
    pull(monkeypatch, finding_id, remote())
    pull(monkeypatch, finding_id, remote("done", "200", revision=2))
    assert read(finding_id)["status"] == "verification_pending"
    assert read(finding_id)["verified_at"] is None
    assert read(finding_id)["verification_requested_at"] is not None
    with SessionLocal.begin() as db:
        finding = db.get(Finding, finding_id)
        finding.status = "open"  # The scanner still observes the finding.
        finding.verification_requested_at = None
        finding.last_seen = _utcnow()
    pull(monkeypatch, finding_id, remote("done", "200", revision=3))
    assert read(finding_id)["status"] == "open"
    with SessionLocal() as db:
        assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == "jira.pull.status"))


@pytest.mark.parametrize("status", ["resolved", "closed", "false_positive", "duplicate"])
def test_remote_updates_preserve_local_terminal_dispositions(monkeypatch, status):
    finding_id = seed(status=status)
    pull(monkeypatch, finding_id, remote())
    pull(monkeypatch, finding_id, remote("done", "200", revision=2))
    assert read(finding_id)["status"] == status


def test_both_sides_status_changes_raise_visible_conflict(monkeypatch):
    finding_id = seed()
    pull(monkeypatch, finding_id, remote())
    with SessionLocal.begin() as db:
        db.get(Finding, finding_id).status = "investigating"
    pull(monkeypatch, finding_id, remote("done", "200", revision=2))
    assert read(finding_id)["status"] == "investigating"
    assert "Both local and Jira status" in read(finding_id)["error"]
    pull(monkeypatch, finding_id, remote("done", "200", revision=3))
    assert "Both local and Jira status" in read(finding_id)["error"]


def test_inflight_local_change_is_not_overwritten(monkeypatch):
    finding_id = seed()
    pull(monkeypatch, finding_id, remote())
    def mutate(self, key):
        with SessionLocal.begin() as db:
            db.get(Finding, finding_id).status = "investigating"
        return remote("done", "200", revision=2)
    monkeypatch.setattr(jira.JiraClient, "issue", mutate)
    make_due(finding_id)
    assert service.process_one()
    assert read(finding_id)["status"] == "investigating"
    assert "during the pull" in read(finding_id)["error"]


def test_inflight_same_value_activity_is_detected(monkeypatch):
    finding_id = seed()
    pull(monkeypatch, finding_id, remote())
    def mutate(self, key):
        with SessionLocal.begin() as db:
            db.add(Comment(finding_id=finding_id, author="analyst", content="Reviewed and reopened"))
        return remote("done", "200", revision=2)
    monkeypatch.setattr(jira.JiraClient, "issue", mutate)
    make_due(finding_id)
    assert service.process_one()
    assert read(finding_id)["status"] == "open"
    assert "during the pull" in read(finding_id)["error"]


@pytest.mark.parametrize("project,role,active", [("other", "analyst", True), ("payments", "viewer", True),
                                               ("payments", "analyst", False)])
def test_remote_identity_cannot_grant_access(monkeypatch, project, role, active):
    finding_id = seed()
    user_id = user(project=project, role=role, active=active)
    with SessionLocal.begin() as db:
        db.add(JiraUserMapping(user_id=user_id, jira_account_id="abc:123"))
    pull(monkeypatch, finding_id, remote())
    pull(monkeypatch, finding_id, remote(owner="abc:123", revision=2))
    assert read(finding_id)["assignee"] is None
    assert "no eligible local identity" in read(finding_id)["error"]


def test_remote_assignment_maps_explicit_eligible_account_only(monkeypatch):
    finding_id = seed()
    user_id = user()
    with SessionLocal.begin() as db:
        db.add(JiraUserMapping(user_id=user_id, jira_account_id="abc:123"))
    pull(monkeypatch, finding_id, remote())
    pull(monkeypatch, finding_id, remote(owner="abc:123", revision=2))
    assert read(finding_id)["assignee"] == "analyst"
    pull(monkeypatch, finding_id, remote(revision=3))
    assert read(finding_id)["assignee"] is None


def test_tenant_change_cannot_redirect_saved_links(monkeypatch):
    finding_id = seed()
    monkeypatch.setenv("JIRA_BASE_URL", "https://other.atlassian.net")
    monkeypatch.setattr(jira.JiraClient, "issue", lambda *_: pytest.fail("unexpected network"))
    assert service.process_one()
    assert read(finding_id)["link_status"] == "failed"
    assert "tenant changed" in read(finding_id)["error"]


def test_global_rate_limit_backoff_and_safe_error(monkeypatch):
    finding_id = seed()
    def limited(*_):
        raise jira.JiraError("Jira rate limit reached; retry is scheduled", retry_after=300)
    monkeypatch.setattr(jira.JiraClient, "issue", limited)
    assert service.process_one()
    assert read(finding_id)["link_status"] == "queued"
    assert not service.process_one()
    with SessionLocal() as db:
        assert db.get(JiraSyncControl, 1).next_request_at > _utcnow() + timedelta(seconds=290)


def test_expired_write_claim_is_never_replayed(monkeypatch):
    finding_id = seed()
    with SessionLocal.begin() as db:
        row = db.get(JiraIssueLink, finding_id)
        row.operation, row.status, row.claim_token = "push_status", "syncing", "stale-token"
        row.claimed_at = _utcnow() - timedelta(seconds=200)
    monkeypatch.setattr(jira.JiraClient, "issue", lambda *_: pytest.fail("unexpected network"))
    assert not service.process_one()
    assert read(finding_id)["link_status"] == "needs_review"


def test_stale_worker_completion_is_fenced(monkeypatch):
    finding_id = seed()
    task = service._claim()
    with SessionLocal.begin() as db:
        db.get(JiraIssueLink, finding_id).claim_token = "new-claim"
    service._finish(task, result={"remote": remote("done", "200"), "pushed": False})
    with SessionLocal() as db:
        assert db.get(JiraIssueLink, finding_id).remote_status is None


def push_payload(finding_id, *, field="status"):
    with SessionLocal() as db:
        finding, row = db.get(Finding, finding_id), db.get(JiraIssueLink, finding_id)
        return {"field": field, "expected_local_status": finding.status,
                "expected_local_assignee": finding.assignee, "expected_remote_updated_at": row.remote_updated_at}


def test_api_preview_queue_and_status_push(monkeypatch, client, auth_headers):
    finding_id = seed(status="investigating")
    pull(monkeypatch, finding_id, remote())
    response = client.get(f"/findings/{finding_id}/jira", headers=auth_headers)
    assert response.status_code == 200, response.text
    assert response.json()["push_preview"]["status_target_category"] == "indeterminate"
    queued = client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers, json=push_payload(finding_id))
    assert queued.status_code == 202, queued.text
    values = iter([remote(), remote("indeterminate", "150", revision=2)])
    monkeypatch.setattr(jira.JiraClient, "issue", lambda *_: next(values))
    transitions = []
    monkeypatch.setattr(jira.JiraClient, "transition", lambda _, key, category: transitions.append((key, category)))
    make_due(finding_id)
    assert service.process_one()
    assert transitions == [("SEC-1", "indeterminate")]
    assert read(finding_id)["link_status"] == "idle"
    assert read(finding_id)["status"] == "investigating"


def test_push_stale_preview_and_local_changes_are_rejected(monkeypatch, client, auth_headers):
    finding_id = seed(status="investigating")
    pull(monkeypatch, finding_id, remote())
    payload = push_payload(finding_id)
    payload["expected_local_status"] = "open"
    assert client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers, json=payload).status_code == 409
    payload = push_payload(finding_id)
    assert client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers, json=payload).status_code == 202
    with SessionLocal.begin() as db:
        db.get(Finding, finding_id).status = "open"
    monkeypatch.setattr(jira.JiraClient, "issue", lambda *_: pytest.fail("stale push must not make network request"))
    make_due(finding_id)
    assert service.process_one()
    assert read(finding_id)["link_status"] == "failed"


def test_changed_remote_progress_prevents_push(monkeypatch, client, auth_headers):
    finding_id = seed(status="investigating")
    pull(monkeypatch, finding_id, remote())
    assert client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers,
                       json=push_payload(finding_id)).status_code == 202
    monkeypatch.setattr(jira.JiraClient, "issue", lambda *_: remote(revision=2))
    monkeypatch.setattr(jira.JiraClient, "transition", lambda *_: pytest.fail("stale remote must not mutate"))
    make_due(finding_id)
    assert service.process_one()
    assert "Jira changed since" in read(finding_id)["error"]


def test_uncertain_push_requires_pull_before_another_push(monkeypatch, client, auth_headers):
    finding_id = seed(status="investigating")
    pull(monkeypatch, finding_id, remote())
    assert client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers,
                       json=push_payload(finding_id)).status_code == 202
    def uncertain(*_):
        raise jira.JiraError("Jira request outcome unknown", uncertain=True)
    monkeypatch.setattr(jira.JiraClient, "transition", uncertain)
    make_due(finding_id)
    assert service.process_one()
    assert read(finding_id)["link_status"] == "needs_review"
    assert client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers,
                       json=push_payload(finding_id)).status_code == 409
    assert client.post(f"/findings/{finding_id}/jira/pull", headers=auth_headers).status_code == 202


@pytest.mark.parametrize("status", ["resolved", "closed", "false_positive", "duplicate"])
def test_local_terminal_status_is_never_mapped_as_fixed_push(monkeypatch, client, auth_headers, status):
    finding_id = seed(status=status)
    pull(monkeypatch, finding_id, remote())
    response = client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers, json=push_payload(finding_id))
    assert response.status_code == 422


def test_mapping_is_explicit_unique_and_writer_only(client, auth_headers):
    analyst, viewer, other = user(), user("viewer", role="viewer"), user("other")
    response = client.put(f"/jira-sync/mappings/{analyst}", headers=auth_headers, json={"jira_account_id": "abc:123"})
    assert response.status_code == 200, response.text
    assert client.put(f"/jira-sync/mappings/{other}", headers=auth_headers,
                      json={"jira_account_id": "abc:123"}).status_code == 409
    assert client.put(f"/jira-sync/mappings/{viewer}", headers=auth_headers,
                      json={"jira_account_id": "viewer-id"}).status_code == 422
    assert client.put(f"/jira-sync/mappings/{analyst}", headers=auth_headers,
                      json={"jira_account_id": "https://other.invalid"}).status_code == 422
    assert len(client.get("/jira-sync/mappings", headers=auth_headers).json()["results"]) == 1


def test_api_project_scope_viewer_and_scanner_boundaries(client, auth_headers, ingest_headers, monkeypatch):
    # Use normal account/session creation helper, with an explicit project grant.
    finding_id = seed(project="payments")
    other_id = seed(project="other")
    monkeypatch.setenv("DASHBOARD_ORIGINS", "http://localhost:5000")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    password = "synthetic-long-password-123"
    response = client.post("/users", headers=auth_headers, json={
        "username": "scoped-viewer", "password": password, "role": "viewer", "projects": ["payments"]})
    assert response.status_code == 201
    response = client.post("/auth/login", headers={"Origin": "http://localhost:5000"},
                           json={"username": "scoped-viewer", "password": password})
    assert response.status_code == 200
    client.headers["Origin"] = "http://localhost:5000"
    assert client.get(f"/findings/{finding_id}/jira").status_code == 200
    assert client.get(f"/findings/{other_id}/jira").status_code == 404
    assert client.post(f"/findings/{finding_id}/jira/pull").status_code == 403
    assert client.get("/jira-sync").status_code == 403
    assert client.get("/jira-sync/mappings").status_code == 403
    assert client.get(f"/findings/{finding_id}/jira", headers=ingest_headers).status_code == 401


def test_approved_assignee_push_uses_explicit_mapping(monkeypatch, client, auth_headers):
    user_id = user()
    finding_id = seed(assignee="analyst")
    with SessionLocal.begin() as db:
        db.add(JiraUserMapping(user_id=user_id, jira_account_id="abc:123"))
    pull(monkeypatch, finding_id, remote())
    response = client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers,
                           json=push_payload(finding_id, field="assignee"))
    assert response.status_code == 202, response.text
    values = iter([remote(), remote(owner="abc:123", revision=2)])
    monkeypatch.setattr(jira.JiraClient, "issue", lambda *_: next(values))
    assignments = []
    monkeypatch.setattr(jira.JiraClient, "assign", lambda _, key, account: assignments.append((key, account)))
    make_due(finding_id)
    assert service.process_one()
    assert assignments == [("SEC-1", "abc:123")]
    assert read(finding_id)["link_status"] == "idle"


def test_mapping_revoked_after_approval_prevents_outbound_push(monkeypatch, client, auth_headers):
    user_id = user()
    finding_id = seed(assignee="analyst")
    with SessionLocal.begin() as db:
        db.add(JiraUserMapping(user_id=user_id, jira_account_id="abc:123"))
    pull(monkeypatch, finding_id, remote())
    assert client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers,
                       json=push_payload(finding_id, field="assignee")).status_code == 202
    with SessionLocal.begin() as db:
        db.get(JiraUserMapping, user_id).active = False
    monkeypatch.setattr(jira.JiraClient, "issue", lambda *_: pytest.fail("must revalidate before network"))
    make_due(finding_id)
    assert service.process_one()
    assert read(finding_id)["link_status"] == "failed"


def test_revoked_requester_cannot_execute_queued_push(monkeypatch, client, auth_headers):
    user_id = user()
    finding_id = seed(status="investigating")
    pull(monkeypatch, finding_id, remote())
    assert client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers,
                       json=push_payload(finding_id)).status_code == 202
    with SessionLocal.begin() as db:
        row = db.get(JiraIssueLink, finding_id)
        pending = json.loads(row.pending_json)
        pending["user_id"], pending["actor"] = user_id, "analyst"
        row.pending_json = json.dumps(pending)
        db.get(User, user_id).active = False
    monkeypatch.setattr(jira.JiraClient, "issue", lambda *_: pytest.fail("revoked requester must not send requests"))
    make_due(finding_id)
    assert service.process_one()
    assert "requesting user no longer" in read(finding_id)["error"]


def test_inflight_push_retains_newer_local_state_and_surfaces_conflict(monkeypatch, client, auth_headers):
    finding_id = seed(status="investigating")
    pull(monkeypatch, finding_id, remote())
    assert client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers,
                       json=push_payload(finding_id)).status_code == 202
    values = iter([remote(), remote("indeterminate", "150", revision=2)])
    monkeypatch.setattr(jira.JiraClient, "issue", lambda *_: next(values))
    def transition(*_):
        with SessionLocal.begin() as db:
            db.get(Finding, finding_id).status = "false_positive"
    monkeypatch.setattr(jira.JiraClient, "transition", transition)
    make_due(finding_id)
    assert service.process_one()
    assert read(finding_id)["status"] == "false_positive"
    assert "while local triage changed" in read(finding_id)["error"]


def test_unobserved_push_completion_requires_review(monkeypatch, client, auth_headers):
    finding_id = seed(status="investigating")
    pull(monkeypatch, finding_id, remote())
    assert client.post(f"/findings/{finding_id}/jira/push", headers=auth_headers,
                       json=push_payload(finding_id)).status_code == 202
    monkeypatch.setattr(jira.JiraClient, "transition", lambda *_: None)
    make_due(finding_id)
    assert service.process_one()
    assert read(finding_id)["link_status"] == "needs_review"


def test_invalid_delivery_reference_is_not_linked_or_requested(monkeypatch):
    finding_id = seed(link=False)
    with SessionLocal.begin() as db:
        row = db.scalar(select(NotificationDelivery).where(NotificationDelivery.finding_id == finding_id))
        row.external_url = "https://other.invalid/browse/SEC-1"
    monkeypatch.setattr(jira.JiraClient, "issue", lambda *_: pytest.fail("invalid evidence must not make requests"))
    assert not service.process_one()
    with SessionLocal() as db:
        assert db.get(JiraIssueLink, finding_id) is None


def test_verified_evidence_is_not_changed_even_on_active_legacy_record(monkeypatch):
    finding_id = seed()
    with SessionLocal.begin() as db:
        db.get(Finding, finding_id).verified_at = _utcnow()
    pull(monkeypatch, finding_id, remote())
    pull(monkeypatch, finding_id, remote("done", "200", revision=2))
    assert read(finding_id)["status"] == "open"
    assert read(finding_id)["verified_at"] is not None


def test_expired_claim_cannot_commit_without_replacement(monkeypatch):
    finding_id = seed()
    task = service._claim()
    with SessionLocal.begin() as db:
        db.get(JiraIssueLink, finding_id).claimed_at = _utcnow() - timedelta(seconds=200)
    service._finish(task, result={"remote": remote("done", "200"), "pushed": False})
    with SessionLocal() as db:
        assert db.get(JiraIssueLink, finding_id).remote_status is None
