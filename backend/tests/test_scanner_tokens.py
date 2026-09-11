"""Scoped scanner credentials never inherit user or legacy global privileges."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import hashlib
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from app import scanner_tokens
from app.db import SessionLocal
from app.models import AuditEvent, Finding, ImportRun, ScannerToken

ORIGIN = "http://localhost:5000"
PASSWORD = "synthetic-scanner-admin-password"


def create(client, auth_headers, project="repo-a", **options):
    response = client.post("/scanner-tokens", headers=auth_headers,
                           json={"name": "Synthetic scanner", "project": project, **options})
    assert response.status_code == 201, response.text
    return response.json()


def scan(client, token, **options):
    return client.post("/import/scan", headers={"X-API-Key": token}, json={
        "parser": "generic-json", "content": '{"title":"Synthetic finding","severity":"low"}',
        **options,
    })


def signal(client, token, project="repo-a"):
    return client.post("/ingest/signal", headers={"X-API-Key": token}, json={
        "tool": "synthetic", "title": "Synthetic signal", "severity": "low", "project": project,
    })


def user_login(client, auth_headers, monkeypatch, role):
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("DASHBOARD_ORIGINS", ORIGIN)
    response = client.post("/users", headers=auth_headers, json={
        "username": role, "password": PASSWORD, "role": role, "projects": None,
    })
    assert response.status_code == 201, response.text
    response = client.post("/auth/login", headers={"Origin": ORIGIN},
                           json={"username": role, "password": PASSWORD})
    assert response.status_code == 200, response.text


def test_plaintext_is_returned_once_and_only_hash_is_stored(client, auth_headers):
    created = create(client, auth_headers, expires_in_days=7)
    token, metadata = created["token"], created["scanner_token"]
    assert token.startswith("secops_ingest_") and len(token.removeprefix("secops_ingest_")) == 64
    assert metadata["name"] == "Synthetic scanner" and metadata["project"] == "repo-a"
    assert metadata["active"] is True and metadata["last_used_at"] is None
    with SessionLocal() as db:
        row = db.get(ScannerToken, metadata["id"])
        assert row.token_hash == hashlib.sha256(token.encode()).hexdigest()
        assert row.expires_at - row.created_at == timedelta(days=7)
        audit = db.scalar(select(AuditEvent).where(AuditEvent.action == "scanner_token.create"))
        assert audit.actor == "api-admin" and audit.user_id is None
        assert token not in audit.details_json and row.token_hash not in audit.details_json
    listing = client.get("/scanner-tokens", headers=auth_headers)
    assert listing.status_code == 200 and listing.json() == {"count": 1, "results": [metadata]}
    assert token not in listing.text and "token_hash" not in listing.text
    assert listing.headers["cache-control"] == "no-store"


def test_scanner_identity_and_scope_survive_rotation_without_user_fk(client, auth_headers):
    created = create(client, auth_headers)
    token_id = created["scanner_token"]["id"]
    identity = scanner_tokens.scanner_principal(created["token"])
    assert identity.id is None and identity.kind == "scanner" and identity.projects == ("repo-a",)
    assert identity.username == f"scanner:{token_id}" and len(identity.username) <= 100
    assert scan(client, created["token"], project="repo-a").status_code == 200
    rotated = client.post(f"/scanner-tokens/{token_id}/rotate", headers=auth_headers,
                          json={"expires_in_days": 365})
    assert rotated.status_code == 200, rotated.text
    result = rotated.json()
    assert result["token"] != created["token"]
    for field in ("id", "project", "name", "created_at"):
        assert result["scanner_token"][field] == created["scanner_token"][field]
    assert result["scanner_token"]["last_used_at"] is None and result["scanner_token"]["revoked_at"] is None
    assert scan(client, created["token"], project="repo-a").status_code == 401
    assert scan(client, result["token"], project="repo-a").status_code == 200
    with SessionLocal() as db:
        assert set(db.scalars(select(ImportRun.actor))) == {f"scanner:{token_id}"}
        assert db.scalar(select(func.count()).select_from(ScannerToken)) == 1
        assert db.get(ScannerToken, token_id).last_used_at is not None


def test_exact_project_and_legacy_default_asset_are_checked_before_import_history(client, auth_headers):
    token = create(client, auth_headers)["token"]
    assert signal(client, token, "repo-a").status_code == 200
    assert signal(client, token, "repo-b").status_code == 404
    assert signal(client, token, "").status_code == 404
    assert scan(client, token, project="repo-a").status_code == 200
    assert scan(client, token, default_asset="repo-a").status_code == 200
    for options in ({}, {"project": "repo-b"}, {"default_asset": "repo-b"},
                    {"project": "repo-b", "default_asset": "repo-a"}):
        assert scan(client, token, **options).status_code == 404
    with SessionLocal() as db:
        assert set(db.scalars(select(Finding.project))) == {"repo-a"}
        assert db.scalar(select(func.count()).select_from(ImportRun)) == 2


def test_empty_project_token_is_explicitly_unscoped_not_global(client, auth_headers):
    token = create(client, auth_headers, project="")["token"]
    assert scan(client, token).status_code == 200
    assert signal(client, token, "").status_code == 200
    assert scan(client, token, default_asset="repo-a").status_code == 404
    assert signal(client, token, "repo-a").status_code == 404


def test_scanner_cannot_read_or_administer_even_with_valid_admin_cookie(client, auth_headers, monkeypatch):
    created = create(client, auth_headers)
    user_login(client, auth_headers, monkeypatch, "admin")
    token_id = created["scanner_token"]["id"]
    for provided in (created["token"], "secops_ingest_" + "a" * 64, "invalid-token"):
        headers = {"X-API-Key": provided, "Origin": ORIGIN, "X-SecOps-User": "admin"}
        for path in ("/findings", "/assets", "/imports", "/users", "/scanner-tokens",
                     "/notifications", "/findings/export.csv", "/saved-views", "/auth/me"):
            assert client.get(path, headers=headers).status_code == 401
        for path, body in (("/scanner-tokens", {"name": "No", "project": "repo-a"}),
                           (f"/scanner-tokens/{token_id}/rotate", {}),
                           (f"/scanner-tokens/{token_id}/revoke", {}),
                           ("/findings/bulk", {"ids": [str(uuid4())], "status": "closed"}),
                           ("/assets/upsert", {"key": "No"})):
            assert client.post(path, headers=headers, json=body).status_code == 401
    assert scan(client, "invalid-token", project="repo-a").status_code == 401
    assert client.get("/auth/me").status_code == 200  # The admin cookie itself remains valid.


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
def test_management_requires_admin_and_cookie_mutations_require_origin(client, auth_headers, monkeypatch, role):
    created = create(client, auth_headers)
    token_id = created["scanner_token"]["id"]
    user_login(client, auth_headers, monkeypatch, role)
    expected = 200 if role == "admin" else 403
    assert client.get("/scanner-tokens").status_code == expected
    for path, body in (("/scanner-tokens", {"name": "User scanner", "project": "repo-a"}),
                       (f"/scanner-tokens/{token_id}/rotate", {}),
                       (f"/scanner-tokens/{token_id}/revoke", {})):
        assert client.post(path, json=body).status_code == 403
        assert client.post(path, headers={"Origin": "https://untrusted.invalid"}, json=body).status_code == 403
        response = client.post(path, headers={"Origin": ORIGIN}, json=body)
        expected_write = (201 if path == "/scanner-tokens" else 200) if role == "admin" else 403
        assert response.status_code == expected_write


def test_expiry_revocation_and_rotation_of_inactive_tokens(client, auth_headers):
    created = create(client, auth_headers)
    token_id = created["scanner_token"]["id"]
    with SessionLocal.begin() as db:
        db.get(ScannerToken, token_id).expires_at = scanner_tokens.utcnow() - timedelta(seconds=1)
    assert signal(client, created["token"]).status_code == 401
    assert client.get("/scanner-tokens", headers=auth_headers).json()["results"][0]["active"] is False
    expired_rotation = client.post(f"/scanner-tokens/{token_id}/rotate", headers=auth_headers).json()
    assert signal(client, expired_rotation["token"]).status_code == 200
    assert client.post(f"/scanner-tokens/{token_id}/revoke", headers=auth_headers).json() == {"ok": True}
    first = client.get("/scanner-tokens", headers=auth_headers).json()["results"][0]
    assert first["active"] is False and first["revoked_at"] is not None
    assert client.post(f"/scanner-tokens/{token_id}/revoke", headers=auth_headers).status_code == 200
    assert client.get("/scanner-tokens", headers=auth_headers).json()["results"][0]["revoked_at"] == first["revoked_at"]
    assert signal(client, expired_rotation["token"]).status_code == 401
    revived = client.post(f"/scanner-tokens/{token_id}/rotate", headers=auth_headers, json={}).json()
    assert revived["scanner_token"]["active"] is True
    assert signal(client, revived["token"]).status_code == 200
    with SessionLocal() as db:
        events = db.scalars(select(AuditEvent).where(AuditEvent.object_id == token_id)).all()
        assert [row.action for row in events].count("scanner_token.revoke") == 1
        assert all(created["token"] not in row.details_json and revived["token"] not in row.details_json for row in events)


def test_legacy_scanner_key_keeps_its_existing_global_ingest_scope(client, ingest_headers, auth_headers):
    key = ingest_headers["X-API-Key"]
    for project in ("repo-a", "repo-b", ""):
        assert scan(client, key, project=project).status_code == 200
    with SessionLocal() as db:
        assert set(db.scalars(select(ImportRun.actor))) == {"scanner"}
    assert client.get("/scanner-tokens", headers=ingest_headers).status_code == 401


@pytest.mark.parametrize("fields", [
    {"name": ""}, {"name": " "}, {"name": "a" * 101}, {"name": "bad\nname"},
    {"project": "a" * 256}, {"project": "😀" * 129}, {"project": "bad\x00project"},
    {"expires_in_days": 0}, {"expires_in_days": 366}, {"expires_in_days": True},
    {"expires_in_days": "90"}, {"token": "supplied-secret"},
])
def test_token_fields_are_bounded_and_secrets_cannot_be_supplied(client, auth_headers, fields):
    response = client.post("/scanner-tokens", headers=auth_headers,
                           json={"name": "Synthetic", "project": "repo-a", **fields})
    assert response.status_code == 422
    assert "supplied-secret" not in response.text
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(ScannerToken)) == 0


def test_unicode_project_grant_matches_ingestion_boundaries(client, auth_headers):
    project = "é" * 255
    token = create(client, auth_headers, project=project)["token"]
    assert signal(client, token, project).status_code == 200


def test_active_and_record_quotas_include_rotation_reactivation(client, auth_headers, monkeypatch):
    monkeypatch.setattr(scanner_tokens, "MAX_ACTIVE_SCANNER_TOKENS", 1)
    monkeypatch.setattr(scanner_tokens, "MAX_SCANNER_TOKENS", 2)
    first = create(client, auth_headers)
    first_id = first["scanner_token"]["id"]
    assert client.post("/scanner-tokens", headers=auth_headers,
                       json={"name": "Second", "project": "repo-a"}).status_code == 422
    client.post(f"/scanner-tokens/{first_id}/revoke", headers=auth_headers)
    second = create(client, auth_headers)
    second_id = second["scanner_token"]["id"]
    assert client.post(f"/scanner-tokens/{first_id}/rotate", headers=auth_headers).status_code == 422
    assert client.post(f"/scanner-tokens/{second_id}/rotate", headers=auth_headers).status_code == 200
    client.post(f"/scanner-tokens/{second_id}/revoke", headers=auth_headers)
    assert client.post("/scanner-tokens", headers=auth_headers,
                       json={"name": "Third", "project": "repo-a"}).status_code == 422
    assert client.post(f"/scanner-tokens/{first_id}/rotate", headers=auth_headers).status_code == 200
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(ScannerToken)) == 2


def test_concurrent_creates_cannot_overrun_active_quota(client, auth_headers, monkeypatch):
    monkeypatch.setattr(scanner_tokens, "MAX_ACTIVE_SCANNER_TOKENS", 1)
    start = Barrier(2)

    def concurrent(name):
        start.wait(timeout=5)
        return client.post("/scanner-tokens", headers=auth_headers,
                           json={"name": name, "project": "repo-a"}).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(concurrent, ("First", "Second"))) == [201, 422]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(ScannerToken)) == 1


def test_concurrent_rotations_leave_exactly_one_current_secret(client, auth_headers):
    created = create(client, auth_headers)
    token_id = created["scanner_token"]["id"]
    start = Barrier(2)

    def concurrent(days):
        start.wait(timeout=5)
        response = client.post(f"/scanner-tokens/{token_id}/rotate", headers=auth_headers,
                               json={"expires_in_days": days})
        assert response.status_code == 200, response.text
        return response.json()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(concurrent, (1, 2)))
    assert all(result["scanner_token"]["id"] == token_id for result in results)
    assert len({result["token"] for result in results}) == 2
    assert signal(client, created["token"]).status_code == 401
    assert sorted(signal(client, result["token"]).status_code for result in results) == [200, 401]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(ScannerToken)) == 1
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "scanner_token.rotate")) == 2
