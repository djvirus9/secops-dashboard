"""Operational catalog, coverage, audit, queue, and remediation workflow tests."""
from datetime import timedelta

import pytest

from app.db import SessionLocal
from app.models import ImportRun
from app.operational import utcnow


ORIGIN = "http://localhost:5000"
PASSWORD = "synthetic-operations-password-123"


@pytest.fixture(autouse=True)
def session_settings(monkeypatch):
    monkeypatch.setenv("DASHBOARD_ORIGINS", ORIGIN)
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")


def create_user(client, auth_headers, username, role="viewer", projects=None):
    response = client.post("/users", headers=auth_headers, json={
        "username": username,
        "password": PASSWORD,
        "role": role,
        "projects": projects,
    })
    assert response.status_code == 201, response.text


def login(client, username):
    response = client.post("/auth/login", headers={"Origin": ORIGIN}, json={
        "username": username,
        "password": PASSWORD,
    })
    assert response.status_code == 200, response.text
    client.headers["Origin"] = ORIGIN


def ingest(client, auth_headers, title, project="payments", tool="semgrep"):
    response = client.post("/ingest/signal", headers=auth_headers, json={
        "project": project,
        "tool": tool,
        "title": title,
        "severity": "high",
        "asset": "api.example.invalid",
    })
    assert response.status_code == 200, response.text
    return response.json()["finding_id"]


def test_catalog_is_admin_only_and_changes_are_audited(client, auth_headers):
    team_response = client.post("/catalog/teams", headers=auth_headers, json={
        "name": "Platform Security",
        "contact": "#platform-security",
    })
    assert team_response.status_code == 201, team_response.text
    team = team_response.json()["team"]
    assert client.post("/catalog/teams", headers=auth_headers, json={
        "name": "platform security",
    }).status_code == 409

    assert client.post("/catalog/projects", headers=auth_headers, json={
        "name": "unsafe",
        "repository_url": "https://user:secret@example.invalid/repository",
    }).status_code == 422
    project_response = client.post("/catalog/projects", headers=auth_headers, json={
        "name": "payments",
        "display_name": "Payments API",
        "team_id": team["id"],
        "business_unit": "Commerce",
        "tier": "critical",
        "repository_url": "https://github.com/example/payments",
    })
    assert project_response.status_code == 201, project_response.text
    assert project_response.json()["project"]["team_name"] == "Platform Security"
    slash_project = client.post("/catalog/projects", headers=auth_headers, json={
        "name": "owner/service", "display_name": "Slash project",
    })
    assert slash_project.status_code == 201
    assert client.patch("/catalog/projects/owner%2Fservice", headers=auth_headers,
                        json={"active": False}).status_code == 200

    ingest(client, auth_headers, "Unmanaged project finding", project="unmanaged")
    catalog = client.get("/catalog", headers=auth_headers).json()
    assert catalog["unmanaged_projects"] == ["unmanaged"]
    assert next(row for row in catalog["projects"] if row["name"] == "payments")["tier"] == "critical"

    patched = client.patch(f"/catalog/teams/{team['id']}", headers=auth_headers,
                           json={"active": False})
    assert patched.status_code == 200 and patched.json()["team"]["active"] is False
    audit = client.get("/audit-events", headers=auth_headers,
                       params={"action": "catalog"}).json()
    assert audit["count"] == 0
    audit = client.get("/audit-events", headers=auth_headers,
                       params={"object_type": "team"}).json()
    assert {row["action"] for row in audit["results"]} == {"team.create", "team.update"}

    create_user(client, auth_headers, "catalog-viewer", projects=["payments"])
    login(client, "catalog-viewer")
    scoped_catalog = client.get("/catalog")
    assert scoped_catalog.status_code == 200
    assert [row["name"] for row in scoped_catalog.json()["projects"]] == ["payments"]
    assert [row["name"] for row in scoped_catalog.json()["teams"]] == ["Platform Security"]
    assert scoped_catalog.json()["unmanaged_projects"] == []
    assert client.get("/audit-events").status_code == 403


def test_coverage_reports_health_and_respects_project_scope(client, auth_headers):
    for source, interval in (("recent", 24), ("old", 24), ("broken", 24), ("never", 24)):
        response = client.post("/coverage", headers=auth_headers, json={
            "project": "payments",
            "source_type": "scanner",
            "source": source,
            "interval_hours": interval,
            "required": True,
        })
        assert response.status_code == 201, response.text
    assert client.post("/coverage", headers=auth_headers, json={
        "project": "identity",
        "source_type": "scanner",
        "source": "recent",
        "interval_hours": 24,
    }).status_code == 201

    now = utcnow()
    with SessionLocal.begin() as db:
        db.add_all([
            ImportRun(parser="recent", project="payments", actor="test", content_sha256="a" * 64,
                      status="completed", imported=0, created_at=now - timedelta(hours=1),
                      completed_at=now - timedelta(hours=1)),
            ImportRun(parser="old", project="payments", actor="test", content_sha256="b" * 64,
                      status="completed", imported=3, created_at=now - timedelta(hours=48),
                      completed_at=now - timedelta(hours=48)),
            ImportRun(parser="broken", project="payments", actor="test", content_sha256="c" * 64,
                      status="failed", error="Synthetic failure", created_at=now - timedelta(minutes=5),
                      completed_at=now - timedelta(minutes=4)),
        ])

    body = client.get("/coverage", headers=auth_headers).json()
    by_source = {row["source"]: row for row in body["results"] if row["project"] == "payments"}
    assert {source: row["health"] for source, row in by_source.items()} == {
        "broken": "failing",
        "never": "missing",
        "old": "stale",
        "recent": "healthy",
    }
    assert by_source["recent"]["last_clean_at"] is not None
    assert body["required_attention"] == 4

    create_user(client, auth_headers, "coverage-viewer", projects=["payments"])
    login(client, "coverage-viewer")
    scoped = client.get("/coverage")
    assert scoped.status_code == 200
    assert scoped.json()["count"] == 4
    assert {row["project"] for row in scoped.json()["results"]} == {"payments"}
    assert client.post("/coverage", json={
        "project": "payments", "source_type": "scanner", "source": "new", "interval_hours": 24,
    }).status_code == 403


def test_my_queue_requires_a_user_session_and_honors_assignments_and_scope(client, auth_headers):
    mine = ingest(client, auth_headers, "My active item")
    closed = ingest(client, auth_headers, "My closed item")
    hidden = ingest(client, auth_headers, "Other project item", project="identity")
    unassigned = ingest(client, auth_headers, "Someone else's item")
    for finding_id, assignee, status in (
        (mine, "alice", "investigating"),
        (closed, "alice", "closed"),
        (hidden, "alice", "open"),
        (unassigned, "bob", "open"),
    ):
        response = client.patch(f"/findings/{finding_id}", headers=auth_headers,
                                json={"assignee": assignee, "status": status})
        assert response.status_code == 200, response.text

    assert client.get("/my-queue", headers=auth_headers).status_code == 403
    create_user(client, auth_headers, "alice", projects=["payments"])
    login(client, "alice")
    queue = client.get("/my-queue").json()
    assert queue["count"] == 1
    assert queue["results"][0]["id"] == mine
    assert queue["results"][0]["status"] == "investigating"


def test_structured_dispositions_and_verification_reopen_safely(client, auth_headers):
    finding_id = ingest(client, auth_headers, "Verify remediation")
    canonical_id = ingest(client, auth_headers, "Canonical issue")
    other_project_id = ingest(client, auth_headers, "Wrong canonical", project="identity")

    assert client.patch(f"/findings/{finding_id}", headers=auth_headers, json={
        "status": "false_positive", "reason": "too short",
    }).status_code == 422
    wrong_target = client.patch(f"/findings/{finding_id}", headers=auth_headers, json={
        "status": "duplicate",
        "reason": "This is linked to a canonical finding in the wrong project.",
        "duplicate_of_id": other_project_id,
    })
    assert wrong_target.status_code == 422

    pending = client.patch(f"/findings/{finding_id}", headers=auth_headers,
                           json={"status": "verification_pending"})
    assert pending.status_code == 200
    assert pending.json()["finding"]["workflow"]["verification_requested_at"] is not None
    assert ingest(client, auth_headers, "Verify remediation") == finding_id
    reopened = client.get(f"/findings/{finding_id}", headers=auth_headers).json()
    assert reopened["status"] == "open"
    assert reopened["workflow"]["verification_requested_at"] is None
    assert reopened["comments"][0]["action_type"] == "verification_failed"

    reason = "Validated test-only behavior with reproducible supporting evidence."
    disposition = client.patch(f"/findings/{finding_id}", headers=auth_headers, json={
        "status": "false_positive", "reason": reason,
    })
    assert disposition.status_code == 200
    assert disposition.json()["finding"]["workflow"]["disposition_reason"] == reason
    assert ingest(client, auth_headers, "Verify remediation") == finding_id
    assert client.get(f"/findings/{finding_id}", headers=auth_headers).json()["status"] == "false_positive"

    duplicate = client.patch(f"/findings/{canonical_id}", headers=auth_headers, json={
        "status": "duplicate",
        "reason": "The scanner evidence matches the original finding and affected component.",
        "duplicate_of_id": finding_id,
    })
    assert duplicate.status_code == 200
    assert duplicate.json()["finding"]["workflow"]["duplicate_of_id"] == finding_id
    assert client.get("/findings", headers=auth_headers,
                      params={"status": "false_positive"}).json()["count"] == 1
    summary = client.get("/dashboard/summary", headers=auth_headers).json()
    assert summary["total_findings"] == 3 and summary["active_findings"] == 1
