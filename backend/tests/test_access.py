from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import hashlib
import json
from threading import Barrier

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import func, select

from app import accounts
from app.db import SessionLocal
from app.main import app
from app.models import AuditEvent, AuthThrottle, Finding, ImportRun, User, UserSession

ORIGIN = "http://localhost:5000"
PASSWORD = "synthetic-password-123"


@pytest.fixture(autouse=True)
def account_settings(monkeypatch):
    monkeypatch.setenv("DASHBOARD_ORIGINS", ORIGIN)
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    monkeypatch.delenv("DASHBOARD_USERNAME", raising=False)
    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)


def create_user(client, headers, username="alice", role="analyst", projects=None):
    response = client.post("/users", headers=headers, json={
        "username": username, "password": PASSWORD, "role": role, "projects": projects,
    })
    assert response.status_code == 201, response.text
    return response.json()["user"]


def login(client, username="alice", password=PASSWORD):
    response = client.post("/auth/login", headers={"Origin": ORIGIN},
                           json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    client.headers["Origin"] = ORIGIN
    return response


def seed_projects(client, headers):
    ids = {}
    for project in ("one", "two", ""):
        response = client.post("/import/scan", headers=headers, json={
            "parser": "generic-json", "project": project,
            "content": json.dumps([{"title": "Synthetic " + project, "severity": "critical",
                                    "asset": "example.invalid"}]),
        })
        assert response.status_code == 200, response.text
        ids[project] = client.get("/findings", headers=headers, params={"project": project}).json()["results"][0]["id"]
    return ids


@pytest.mark.parametrize(("role", "can_write", "is_admin"), [
    ("viewer", False, False), ("analyst", True, False), ("admin", True, True),
])
def test_roles_and_project_scope_cover_lists_aggregates_and_objects(client, auth_headers, role, can_write, is_admin):
    ids = seed_projects(client, auth_headers)
    create_user(client, auth_headers, role=role, projects=["one"])
    login(client)
    expected = 3 if is_admin else 1
    for path in ("/findings", "/assets", "/risks", "/risks/assets", "/imports"):
        response = client.get(path)
        assert response.status_code == 200, response.text
        assert response.json()["count"] == expected
        if not is_admin:
            assert {row["project"] for row in response.json()["results"]} == {"one"}
    summary = client.get("/dashboard/summary").json()
    assert summary["total_findings"] == summary["active_findings"] == summary["critical_findings"] == summary["assets"] == expected
    assert summary["active_by_severity"] == {"critical": expected}
    assert client.get("/parsers").status_code == 200
    assert client.get(f"/findings/{ids['one']}").status_code == 200
    assert client.get(f"/findings/{ids['two']}").status_code == (200 if is_admin else 404)
    assert client.get("/findings", params={"project": "two", "q": "Synthetic"}).json()["count"] == (1 if is_admin else 0)
    for path in ("/users", "/notifications", "/integrations", "/docs", "/openapi.json", "/redoc"):
        assert client.get(path).status_code == (200 if is_admin else 403)
    response = client.patch(f"/findings/{ids['one']}", json={"status": "investigating"})
    assert response.status_code == (200 if can_write else 403)
    response = client.post(f"/findings/{ids['one']}/comments", json={"content": "Synthetic triage note"},
                           headers={"X-SecOps-User": "pretend-admin"})
    assert response.status_code == (200 if can_write else 403)
    if can_write:
        assert response.json()["comment"]["author"] == "alice"
    if role == "analyst":
        assert client.patch(f"/findings/{ids['two']}", json={"status": "closed"}).status_code == 404
        assert client.post(f"/findings/{ids['two']}/comments", json={"content": "Denied"}).status_code == 404


@pytest.mark.parametrize("projects,expected", [(None, 3), ([], 0), ([""], 1)])
def test_all_none_and_unscoped_project_grants_are_distinct(client, auth_headers, projects, expected):
    seed_projects(client, auth_headers)
    create_user(client, auth_headers, role="viewer", projects=projects)
    login(client)
    assert client.get("/findings").json()["count"] == expected
    assert client.get("/dashboard/summary").json()["assets"] == expected


def test_project_grants_match_api_character_and_utf8_byte_boundaries(client, auth_headers):
    project = "é" * 255  # The API permits 255 characters and at most 512 UTF-8 bytes.
    user = create_user(client, auth_headers, projects=[project])
    assert user["projects"] == [project]
    login(client)
    payload = {"project": project, "asset": "example.invalid", "tool": "synthetic",
               "title": "Scoped Unicode project", "severity": "low"}
    assert client.post("/ingest/signal", json=payload).status_code == 200
    listed = client.get("/findings", params={"project": project}).json()
    assert listed["count"] == 1 and listed["results"][0]["project"] == project

    for invalid in ("a" * 256, "😀" * 129):
        response = client.post("/users", headers=auth_headers, json={
            "username": "invalid-grant", "password": PASSWORD, "role": "viewer", "projects": [invalid],
        })
        assert response.status_code == 422
        assert client.post("/ingest/signal", headers=auth_headers,
                           json={**payload, "project": invalid}).status_code == 422


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_write_routes_enforce_role_and_project_before_import_history(client, auth_headers, role):
    create_user(client, auth_headers, role=role, projects=["one"])
    login(client)
    for project in ("one", "two"):
        expected = 403 if role == "viewer" else 200 if project == "one" else 404
        requests = [
            ("/assets/upsert", {"project": project, "key": "example.invalid"}),
            ("/ingest/signal", {"project": project, "asset": "example.invalid", "tool": "synthetic", "title": "Synthetic", "severity": "low"}),
            ("/import/scan", {"project": project, "parser": "generic-json", "content": '{"findings":[]}'}),
            # Legacy default_asset is an effective project and must also be checked.
            ("/import/scan", {"default_asset": project, "parser": "generic-json", "content": '{"findings":[]}'}),
        ]
        for path, payload in requests:
            assert client.post(path, json=payload).status_code == expected
    with SessionLocal() as db:
        assert (db.scalar(select(func.count()).select_from(ImportRun)) or 0) == (2 if role == "analyst" else 0)
        assert set(db.scalars(select(Finding.project))) <= {"one"}


def test_session_cookie_hash_flags_and_api_identity_cannot_be_spoofed(client, auth_headers, monkeypatch):
    user = create_user(client, auth_headers)
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "true")
    response = login(client)
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "secure" in cookie and "path=/" in cookie
    token = response.cookies.get("secops_session")
    with SessionLocal() as db:
        session = db.scalar(select(UserSession))
        stored = db.get(User, user["id"])
        assert session.token_hash == hashlib.sha256(token.encode()).hexdigest()
        assert token not in session.token_hash
        assert stored.password_hash.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
        assert PASSWORD not in stored.password_hash
    assert "password" not in json.dumps(response.json()).lower()
    assert client.get("/auth/me", headers=auth_headers).status_code == 403
    assert client.get("/users", headers={**auth_headers, "X-SecOps-User": "alice"}).status_code == 200


def test_login_and_cookie_writes_require_exact_origin_without_trusting_host(client, auth_headers):
    create_user(client, auth_headers)
    for origin in (None, "null", "https://evil.invalid", ORIGIN + ".evil.invalid", ORIGIN + "/"):
        headers = {"X-Forwarded-Host": "localhost:5000", "X-Forwarded-Proto": "http"}
        if origin is not None:
            headers["Origin"] = origin
        assert client.post("/auth/login", headers=headers, json={"username": "alice", "password": PASSWORD}).status_code == 403
    login(client)
    del client.headers["Origin"]
    assert client.get("/auth/me").status_code == 200
    assert client.post("/auth/logout").status_code == 403
    assert client.post("/auth/logout", headers={"Origin": "https://evil.invalid"}).status_code == 403
    assert client.post("/auth/logout", headers={"Origin": ORIGIN}).status_code == 200
    assert client.get("/auth/me").status_code == 401


@pytest.mark.parametrize("state", ["expired", "idle", "revoked", "disabled"])
def test_expired_idle_revoked_and_disabled_sessions_fail_closed(client, auth_headers, state):
    user = create_user(client, auth_headers)
    login(client)
    with SessionLocal.begin() as db:
        session = db.scalar(select(UserSession))
        if state == "expired":
            session.expires_at = accounts.utcnow() - timedelta(seconds=1)
        elif state == "idle":
            session.last_seen_at = accounts.utcnow() - timedelta(hours=1)
        elif state == "revoked":
            session.revoked_at = accounts.utcnow()
        else:
            db.get(User, user["id"]).active = False
    assert client.get("/findings").status_code == 401


@pytest.mark.parametrize("change", [
    {"role": "viewer"}, {"active": False}, {"projects": []}, {"password": "new-synthetic-password-123"},
])
def test_account_changes_revoke_existing_sessions(client, auth_headers, change):
    user = create_user(client, auth_headers)
    login(client)
    assert client.patch(f"/users/{user['id']}", headers=auth_headers, json=change).status_code == 200
    assert client.get("/auth/me").status_code == 401
    with SessionLocal() as db:
        assert db.scalar(select(UserSession.revoked_at)) is not None
        audit = db.scalar(select(AuditEvent).where(AuditEvent.action == "user.updated"))
        assert audit.actor == "api-admin"
        assert "new-synthetic-password" not in audit.details_json


def test_password_change_and_operator_recovery_revoke_all_sessions(client, auth_headers):
    create_user(client, auth_headers)
    login(client)
    with TestClient(app) as other:
        login(other)
        response = client.post("/auth/password", json={"current_password": PASSWORD, "new_password": "replacement-password-123"})
        assert response.status_code == 200
        assert client.get("/auth/me").status_code == other.get("/auth/me").status_code == 401
    login(client, password="replacement-password-123")
    accounts.reset_password("alice", PASSWORD)
    assert client.get("/auth/me").status_code == 401
    with SessionLocal() as db:
        assert db.scalar(select(AuditEvent.actor).where(AuditEvent.action == "user.password_reset")) == "local-recovery"


def test_bootstrap_is_idempotent_and_never_overwrites_existing_password(monkeypatch):
    monkeypatch.setenv("DASHBOARD_USERNAME", "Admin")
    monkeypatch.setenv("DASHBOARD_PASSWORD", PASSWORD)
    accounts.bootstrap_admin()
    with SessionLocal() as db:
        first = db.scalar(select(User))
        original_id, original_hash = first.id, first.password_hash
    monkeypatch.setenv("DASHBOARD_PASSWORD", "different-environment-password")
    accounts.bootstrap_admin()
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 1
        user = db.get(User, original_id)
        assert user.username == "admin" and user.role == "admin" and user.projects_json is None
        assert user.password_hash == original_hash


def test_concurrent_first_start_creates_exactly_one_bootstrap_admin(monkeypatch):
    monkeypatch.setenv("DASHBOARD_USERNAME", "admin")
    monkeypatch.setenv("DASHBOARD_PASSWORD", PASSWORD)
    barrier = Barrier(2)

    def bootstrap(_):
        barrier.wait(timeout=5)
        accounts.bootstrap_admin()

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(bootstrap, range(2)))
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 1
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "user.bootstrap")) == 1


@pytest.mark.parametrize("settings", [{"DASHBOARD_USERNAME": "admin"}, {"DASHBOARD_PASSWORD": PASSWORD},
                                      {"DASHBOARD_USERNAME": "admin", "DASHBOARD_PASSWORD": "short"}])
def test_partial_or_invalid_bootstrap_fails_without_creating_users(monkeypatch, settings):
    for name, value in settings.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError):
        accounts.bootstrap_admin()
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 0


def test_last_active_administrator_is_preserved_under_concurrent_changes(client, auth_headers):
    users = [create_user(client, auth_headers, username=name, role="admin") for name in ("first", "second")]
    barrier = Barrier(2)

    def disable(user):
        barrier.wait(timeout=5)
        return client.patch(f"/users/{user['id']}", headers=auth_headers, json={"active": False}).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(disable, users)) == [200, 409]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.active.is_(True))) == 1


def test_login_throttle_is_persistent_account_and_global_and_errors_are_generic(client, auth_headers, monkeypatch):
    create_user(client, auth_headers)
    monkeypatch.setattr(accounts, "password_matches", lambda *_: False)
    body = {"username": "alice", "password": "wrong"}
    responses = [client.post("/auth/login", headers={"Origin": ORIGIN}, json=body) for _ in range(11)]
    assert all(response.status_code == 401 for response in responses[:10])
    assert responses[-1].status_code == 429
    with TestClient(app) as other:
        assert other.post("/auth/login", headers={"Origin": ORIGIN}, json=body).status_code == 429
        for index in range(29):
            response = other.post("/auth/login", headers={"Origin": ORIGIN, "X-Forwarded-For": f"192.0.2.{index}"},
                                  json={"username": f"unknown-{index}", "password": "wrong"})
        assert response.status_code == 429
    with SessionLocal() as db:
        rows = db.scalars(select(AuthThrottle)).all()
        assert len(rows) <= 1024 and all(len(row.key) == 64 for row in rows)
    assert "alice" not in responses[0].text and "wrong" not in responses[0].text


def test_login_throttle_capacity_is_bounded_and_expired_entries_are_pruned(client):
    now = accounts.utcnow()
    with SessionLocal.begin() as db:
        db.add_all(AuthThrottle(key=hashlib.sha256(str(index).encode()).hexdigest(),
                                window_start=now, updated_at=now, failures=1)
                   for index in range(1024))
    response = client.post("/auth/login", headers={"Origin": ORIGIN},
                           json={"username": "unknown", "password": "wrong"})
    assert response.status_code == 429
    with SessionLocal.begin() as db:
        assert db.scalar(select(func.count()).select_from(AuthThrottle)) == 1024
        for row in db.scalars(select(AuthThrottle)):
            row.updated_at = now - timedelta(minutes=16)
    response = client.post("/auth/login", headers={"Origin": ORIGIN},
                           json={"username": "unknown", "password": "wrong"})
    assert response.status_code == 401
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(AuthThrottle)) == 2


@pytest.mark.parametrize("username,expected", [("\x00", 401), ("\ud800", 422), (" ", 401), ("unknown-user", 401)])
def test_invalid_or_missing_accounts_do_not_leak_errors(client, username, expected):
    response = client.post(
        "/auth/login", headers={"Origin": ORIGIN, "Content-Type": "application/json"},
        content=json.dumps({"username": username, "password": "wrong"}))
    assert response.status_code == expected
    if expected == 401:
        assert response.json() == {"detail": "Invalid username or password"}
    else:
        assert "input" not in response.text and "wrong" not in response.text
