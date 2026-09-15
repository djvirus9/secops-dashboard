"""Ownership is actionable, bounded and never an implicit access grant."""
import json
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.db import SessionLocal
from app.models import AuditEvent, Comment, Finding, TeamMembership, User, _utcnow

PASSWORD = "synthetic-ownership-password-12345"
ORIGIN = "http://localhost:5000"


@pytest.fixture(autouse=True)
def cookies(monkeypatch):
    monkeypatch.setenv("DASHBOARD_ORIGINS", ORIGIN)
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")


def account(client, headers, username, *, projects=None, role="analyst", active=True):
    response = client.post("/users", headers=headers, json={
        "username": username, "password": PASSWORD, "role": role, "projects": projects,
    })
    assert response.status_code == 201, response.text
    user = response.json()["user"]
    if not active:
        with SessionLocal.begin() as db:
            db.get(User, user["id"]).active = False
    return user


def login(client, username):
    response = client.post("/auth/login", headers={"Origin": ORIGIN},
                           json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    client.headers["Origin"] = ORIGIN


def signal(client, headers, *, project="payments", title="Synthetic ownership finding"):
    response = client.post("/ingest/signal", headers=headers, json={
        "project": project, "tool": "ownership-test", "title": title,
        "asset": "example.invalid", "severity": "high",
    })
    assert response.status_code == 200, response.text
    return response.json()["finding_id"]


def setup_team(client, headers, name="Owners", projects=("payments",)):
    response = client.post("/catalog/teams", headers=headers, json={"name": name})
    assert response.status_code == 201, response.text
    team = response.json()["team"]
    for project in projects:
        assert client.post("/catalog/projects", headers=headers, json={
            "name": project, "team_id": team["id"],
        }).status_code == 201
    return team


def add_member(client, headers, team, user):
    response = client.put(f"/ownership/teams/{team['id']}/members/{user['id']}", headers=headers)
    assert response.status_code == 200, response.text


def rule(client, headers, *, project="payments", assignee=None, enabled=True):
    return client.put("/ownership/rules", headers=headers, params={"project": project},
                      json={"enabled": enabled, "default_assignee": assignee})


def test_eligible_assignees_are_active_writers_with_exact_project_grants(client, auth_headers):
    unusual = 'owner/service %_ "雪"'
    account(client, auth_headers, "exact", projects=[unusual])
    account(client, auth_headers, "partial", projects=["owner/service"])
    account(client, auth_headers, "viewer", projects=[unusual], role="viewer")
    account(client, auth_headers, "inactive", projects=[unusual], active=False)
    account(client, auth_headers, "global")
    account(client, auth_headers, "admin", projects=[], role="admin")
    account(client, auth_headers, "empty", projects=[""])
    rows = client.get("/ownership/assignees", headers=auth_headers, params={"project": unusual}).json()
    assert {row["username"] for row in rows["results"]} == {"exact", "global", "admin"}
    assert rows["count"] == 3
    assert client.get("/ownership/assignees", headers=auth_headers, params={"project": unusual, "limit": 1}).json()["count"] == 3
    empty = client.get("/ownership/assignees", headers=auth_headers).json()
    assert {row["username"] for row in empty["results"]} == {"global", "admin", "empty"}
    login(client, "exact")
    assert client.get("/ownership/assignees", params={"project": "private"}).status_code == 404
    assert client.get("/ownership/assignees", params={"project": unusual, "limit": 201}).status_code == 422


@pytest.mark.parametrize("grants", ['["payments",', '{"payments": true}', '"payments"', '["payments", 1]', 'null'])
def test_corrupt_or_nonstring_grants_fail_closed_in_options_and_queues(client, auth_headers, grants):
    user = account(client, auth_headers, "corrupt")
    finding_id = signal(client, auth_headers)
    with SessionLocal.begin() as db:
        db.get(User, user["id"]).projects_json = grants
        db.get(Finding, finding_id).assignee = "corrupt"
    assert client.get("/ownership/assignees", headers=auth_headers, params={"project": "payments"}).json()["count"] == 0
    queue = client.get("/ownership/queue", headers=auth_headers).json()
    assert queue["count"] == 1
    assert queue["results"][0]["ownership"]["status"] == "invalid_assignee"
    assert client.patch(f"/findings/{finding_id}", headers=auth_headers, json={"assignee": "corrupt"}).status_code == 422


def test_single_assignment_rejects_unknown_inactive_viewer_and_wrong_grants_atomically(client, auth_headers):
    account(client, auth_headers, "owner", projects=["payments"])
    account(client, auth_headers, "viewer", role="viewer")
    account(client, auth_headers, "inactive", active=False)
    account(client, auth_headers, "wrong", projects=["payments-other"])
    finding_id = signal(client, auth_headers)
    for name in ("typo", "viewer", "inactive", "wrong"):
        response = client.patch(f"/findings/{finding_id}", headers=auth_headers,
                                json={"assignee": name, "status": "resolved"})
        assert response.status_code == 422, response.text
    with SessionLocal() as db:
        row = db.get(Finding, finding_id)
        assert row.status == "open" and row.assignee is None
        assert db.scalar(select(func.count()).select_from(Comment)) == 0
    assert client.patch(f"/findings/{finding_id}", headers=auth_headers, json={"assignee": "owner"}).status_code == 200
    assert client.get("/ownership/queue", headers=auth_headers).json()["count"] == 0
    cleared = client.patch(f"/findings/{finding_id}", headers=auth_headers, json={"assignee": None})
    assert cleared.status_code == 200 and cleared.json()["finding"]["assignee"] is None
    assert client.patch(f"/findings/{finding_id}", headers=auth_headers, json={"assignee": "owner"}).status_code == 200
    assert client.patch(f"/findings/{finding_id}", headers=auth_headers, json={"assignee": ""}).json()["finding"]["assignee"] is None


def test_bulk_assignment_checks_every_project_before_mutations(client, auth_headers):
    account(client, auth_headers, "payments-only", projects=["payments"])
    first, second = signal(client, auth_headers), signal(client, auth_headers, project="private")
    response = client.post("/findings/bulk", headers=auth_headers,
                           json={"ids": [first, second], "assignee": "payments-only", "status": "resolved"})
    assert response.status_code == 422, response.text
    with SessionLocal() as db:
        assert all(row.status == "open" and row.assignee is None for row in db.scalars(select(Finding)))
        assert db.scalar(select(func.count()).select_from(Comment)) == 0
    login(client, "payments-only")
    response = client.post("/findings/bulk", json={"ids": [first, second], "assignee": "typo"})
    assert response.status_code == 404  # Does not reveal hidden selection metadata.


def test_memberships_are_admin_managed_bounded_audited_and_not_access_grants(client, auth_headers, monkeypatch):
    team = setup_team(client, auth_headers, projects=("payments", "private"))
    user = account(client, auth_headers, "member", projects=["payments"])
    viewer = account(client, auth_headers, "viewer", role="viewer")
    add_member(client, auth_headers, team, user)
    add_member(client, auth_headers, team, user)  # Idempotent, one event.
    path = f"/ownership/teams/{team['id']}/members/{viewer['id']}"
    assert client.put(path, headers=auth_headers).status_code == 422
    monkeypatch.setattr("app.ownership.MAX_TEAM_MEMBERS", 1)
    extra = account(client, auth_headers, "extra")
    assert client.put(f"/ownership/teams/{team['id']}/members/{extra['id']}", headers=auth_headers).status_code == 422
    signal(client, auth_headers, project="payments")
    private = signal(client, auth_headers, project="private")
    login(client, "member")
    assert client.get("/ownership/my-teams").json()["results"][0]["id"] == team["id"]
    assert client.get(f"/ownership/teams/{team['id']}/members").status_code == 403
    assert client.put(path).status_code == 403
    queue = client.get("/ownership/queue", params={"view": "team", "team_id": team["id"]}).json()
    assert queue["count"] == 1 and queue["results"][0]["project"] == "payments"
    assert client.get(f"/findings/{private}").status_code == 404
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(TeamMembership)) == 1
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "team.member_added")) == 1


def test_team_queue_requires_real_identity_or_explicit_admin_team_scope(client, auth_headers):
    team = setup_team(client, auth_headers)
    account(client, auth_headers, "outsider", projects=["payments"])
    signal(client, auth_headers)
    assert client.get("/ownership/my-teams", headers=auth_headers).status_code == 403
    assert client.get("/ownership/queue", headers=auth_headers, params={"view": "team"}).status_code == 403
    assert client.get("/ownership/queue", headers=auth_headers, params={"view": "team", "team_id": team["id"]}).json()["count"] == 1
    login(client, "outsider")
    assert client.get("/ownership/queue", params={"view": "team"}).json()["count"] == 0
    assert client.get("/ownership/queue", params={"view": "team", "team_id": team["id"]}).status_code == 404


def test_routing_opt_in_new_only_and_invalid_default_is_actionable(client, auth_headers):
    team = setup_team(client, auth_headers)
    owner = account(client, auth_headers, "owner", projects=["payments"])
    other = account(client, auth_headers, "other", projects=["payments"])
    old = signal(client, auth_headers, title="Before routing")
    assert rule(client, auth_headers, assignee="owner").status_code == 422  # Not yet a member.
    add_member(client, auth_headers, team, owner)
    assert rule(client, auth_headers, assignee="owner").status_code == 200
    new = signal(client, auth_headers, title="New routed")
    with SessionLocal() as db:
        assert db.get(Finding, old).assignee is None
        assert db.get(Finding, new).assignee == "owner"
    assert client.patch(f"/findings/{new}", headers=auth_headers, json={"assignee": "other"}).status_code == 200
    signal(client, auth_headers, title="New routed")
    with SessionLocal() as db:
        assert db.get(Finding, new).assignee == "other"
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "ownership.routed")) == 1
    assert client.delete(f"/ownership/teams/{team['id']}/members/{owner['id']}", headers=auth_headers).status_code == 204
    skipped = signal(client, auth_headers, title="Removed owner")
    with SessionLocal() as db:
        assert db.get(Finding, skipped).assignee is None
        assert db.scalar(select(Comment).where(Comment.finding_id == skipped)).action_type == "ownership"
    details = client.get("/ownership/rules", headers=auth_headers, params={"project": "payments"}).json()["results"][0]
    assert details["enabled"] and not details["ready"] and details["warning"]


def test_route_to_team_queue_without_default_and_never_route_terminal(client, auth_headers):
    from app.ownership import route_new_finding

    setup_team(client, auth_headers)
    assert rule(client, auth_headers).status_code == 200
    finding_id = signal(client, auth_headers)
    with SessionLocal.begin() as db:
        row = db.get(Finding, finding_id)
        assert row.assignee is None
        assert "team member must claim" in db.scalar(select(Comment.content).where(Comment.finding_id == finding_id))
        row.status = "resolved"
        route_new_finding(db, row)
        db.flush()
        assert db.scalar(select(func.count()).select_from(Comment)) == 1


def test_unassigned_includes_invalid_legacy_owners_preserves_history_and_orders_risk(client, auth_headers):
    owner = account(client, auth_headers, "owner", projects=["payments"])
    first = signal(client, auth_headers, title="Legacy owner")
    second = signal(client, auth_headers, title="Disabled owner")
    third = signal(client, auth_headers, title="Resolved not actionable")
    with SessionLocal.begin() as db:
        db.get(User, owner["id"]).active = False
        one, two, three = [db.get(Finding, key) for key in (first, second, third)]
        one.assignee, one.priority_score = "historical-typo", 99
        one.remediation_due_at = _utcnow() - timedelta(days=1)
        two.assignee, two.priority_score = "owner", 10
        three.assignee, three.status = "unknown", "resolved"
    response = client.get("/ownership/queue", headers=auth_headers, params={"limit": 1}).json()
    assert response["count"] == 2 and response["overdue"] == 1
    assert response["results"][0]["id"] == first
    assert response["results"][0]["assignee"] == "historical-typo"
    assert response["results"][0]["ownership"]["status"] == "invalid_assignee"
    with SessionLocal() as db:
        assert db.get(Finding, first).assignee == "historical-typo"
        assert db.scalar(select(func.count()).select_from(Comment)) == 0


def test_import_routes_new_findings_once(client, auth_headers):
    team = setup_team(client, auth_headers)
    owner = account(client, auth_headers, "owner", projects=["payments"])
    add_member(client, auth_headers, team, owner)
    assert rule(client, auth_headers, assignee="owner").status_code == 200
    payload = {"parser": "generic-json", "project": "payments", "content": json.dumps([
        {"title": "Imported route", "severity": "high", "asset": "example.invalid"},
    ])}
    for _ in range(2):
        response = client.post("/import/scan", headers=auth_headers, json=payload)
        assert response.status_code == 200, response.text
    with SessionLocal() as db:
        assert db.scalar(select(Finding)).assignee == "owner"
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "ownership.routed")) == 1


def test_github_routes_new_open_alerts_and_keeps_local_assignments(client, auth_headers, monkeypatch):
    from app.github_sync import client as github, service

    monkeypatch.setenv("GITHUB_SYNC_TOKEN", "synthetic-routing-fixture-token")
    alerts = [github.RemoteAlert(source="code_scanning", number=1, state="open", title="Routed GitHub", severity="high"),
              github.RemoteAlert(source="code_scanning", number=2, state="fixed", title="Already fixed", severity="high")]
    monkeypatch.setattr(github, "fetch_alerts", lambda *_: list(alerts))
    team = setup_team(client, auth_headers)
    owner = account(client, auth_headers, "owner", projects=["payments"])
    account(client, auth_headers, "manual", projects=["payments"])
    add_member(client, auth_headers, team, owner)
    assert rule(client, auth_headers, assignee="owner").status_code == 200
    response = client.post("/github-sync", headers=auth_headers, json={
        "repository": "fixture/payments", "project": "payments", "sources": ["code_scanning"],
    })
    assert response.status_code == 201, response.text
    connection = response.json()["connection"]
    assert service.process_one()
    with SessionLocal() as db:
        finding = db.scalar(select(Finding).where(Finding.title == "Routed GitHub"))
        finding_id = finding.id
        assert finding.assignee == "owner"
        assert db.scalar(select(Finding).where(Finding.title == "Already fixed")).assignee is None
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "ownership.routed")) == 1
    assert client.patch(f"/findings/{finding_id}", headers=auth_headers, json={"assignee": "manual"}).status_code == 200
    assert client.post(f"/github-sync/{connection['id']}/sync", headers=auth_headers).status_code == 202
    assert service.process_one()
    with SessionLocal() as db:
        assert db.get(Finding, finding_id).assignee == "manual"
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "ownership.routed")) == 1


def test_routing_and_all_queues_respect_project_scope_and_inactive_configuration(client, auth_headers):
    team = setup_team(client, auth_headers, projects=("payments", "private"))
    owner = account(client, auth_headers, "owner", projects=["payments"])
    add_member(client, auth_headers, team, owner)
    assert rule(client, auth_headers, assignee="owner").status_code == 200
    assert rule(client, auth_headers, project="private", assignee="owner").status_code == 422
    assert client.patch(f"/catalog/teams/{team['id']}", headers=auth_headers, json={"active": False}).status_code == 200
    public_id = signal(client, auth_headers)
    signal(client, auth_headers, project="private")
    with SessionLocal() as db:
        assert db.get(Finding, public_id).assignee is None
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "ownership.routing_skipped")) is not None
    login(client, "owner")
    assert rule(client, {}, enabled=False).status_code == 403
    assert client.get("/ownership/rules").json()["count"] == 1
    assert client.get("/ownership/rules", params={"project": "private"}).status_code == 404
    assert client.get("/ownership/queue").json()["count"] == 1
    assert client.get("/ownership/queue", params={"view": "team"}).json()["count"] == 1
    assert client.get("/ownership/queue", params={"view": "team", "project": "private"}).status_code == 404


def test_demoted_assignee_moves_from_my_queue_to_needs_owner_without_erasing_history(client, auth_headers):
    user = account(client, auth_headers, "owner", projects=["payments"])
    finding_id = signal(client, auth_headers)
    assert client.patch(f"/findings/{finding_id}", headers=auth_headers, json={"assignee": "owner"}).status_code == 200
    login(client, "owner")
    assert client.get("/my-queue").json()["count"] == 1
    assert client.patch(f"/users/{user['id']}", headers=auth_headers, json={"role": "viewer"}).status_code == 200
    login(client, "owner")
    assert client.get("/my-queue").json()["count"] == 0
    queue = client.get("/ownership/queue").json()
    assert queue["count"] == 1 and queue["results"][0]["id"] == finding_id
    assert queue["results"][0]["assignee"] == "owner"
    assert queue["results"][0]["ownership"]["status"] == "invalid_assignee"


def test_catalog_ownership_edits_share_assignment_lifecycle_lock(client, auth_headers, monkeypatch):
    from app import operational

    team = setup_team(client, auth_headers)
    real_lock = operational._lock_accounts
    calls = []

    def record(db):
        calls.append(True)
        return real_lock(db)

    monkeypatch.setattr(operational, "_lock_accounts", record)
    assert client.patch(f"/catalog/teams/{team['id']}", headers=auth_headers, json={"active": False}).status_code == 200
    assert client.patch("/catalog/projects/payments", headers=auth_headers, json={"team_id": None}).status_code == 200
    assert len(calls) == 2
