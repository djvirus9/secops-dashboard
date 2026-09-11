"""Authorization and data-integrity regressions for team triage and downloads."""
import csv
import io
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event, Lock
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.db import SessionLocal
from app.models import AuditEvent, Comment, Finding, SavedView

ORIGIN = "http://localhost:5000"
PASSWORD = "synthetic-team-password-12345"


@pytest.fixture(autouse=True)
def cookie_settings(monkeypatch):
    monkeypatch.setenv("DASHBOARD_ORIGINS", ORIGIN)
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")


def account(client, auth_headers, username, role="analyst", projects=None):
    response = client.post("/users", headers=auth_headers, json={
        "username": username, "password": PASSWORD, "role": role,
        "projects": ["allowed"] if projects is None else projects,
    })
    assert response.status_code == 201, response.text
    return response.json()["user"]


def login(client, username):
    response = client.post("/auth/login", headers={"Origin": ORIGIN},
                           json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"Origin": ORIGIN}


def signal(client, auth_headers, title="Synthetic finding", project="allowed", severity="high"):
    response = client.post("/ingest/signal", headers=auth_headers, json={
        "tool": "workflow-tests", "title": title, "severity": severity,
        "project": project, "asset": "scanner.example.invalid",
    })
    assert response.status_code == 200, response.text
    return response.json()["finding_id"]


def csv_rows(response):
    assert response.status_code == 200, response.text
    return list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"), newline="")))


def test_saved_views_are_private_even_from_other_administrators(client, auth_headers):
    first = account(client, auth_headers, "first", "viewer")
    account(client, auth_headers, "second", "admin")
    headers = login(client, "first")
    created = client.post("/saved-views", headers=headers, json={
        "name": "My critical queue", "filters": {"project": "allowed", "severity": "critical", "sort": "risk_desc"},
    })
    assert created.status_code == 201, created.text
    view = created.json()
    assert client.get("/saved-views").json()["results"] == [view]
    assert client.post("/saved-views", headers=headers, json={"name": view["name"], "filters": {}}).status_code == 409
    renamed = client.patch(f"/saved-views/{view['id']}", headers=headers, json={"name": "Critical work"})
    assert renamed.status_code == 200
    assert renamed.json()["filters"] == view["filters"]

    headers = login(client, "second")
    assert client.get("/saved-views").json()["results"] == []
    assert client.patch(f"/saved-views/{view['id']}", headers=headers, json={"name": "Take over"}).status_code == 404
    assert client.delete(f"/saved-views/{view['id']}", headers=headers).status_code == 404
    assert client.get("/saved-views", headers={**auth_headers, "X-SecOps-User": "first"}).status_code == 403
    with SessionLocal() as db:
        assert db.get(SavedView, view["id"]).user_id == first["id"]

    headers = login(client, "first")
    assert client.delete(f"/saved-views/{view['id']}", headers=headers).status_code == 204
    assert client.get("/saved-views").json()["results"] == []


def test_saved_view_limits_and_invalid_filters_fail_without_new_rows(client, auth_headers, monkeypatch):
    account(client, auth_headers, "viewer", "viewer")
    headers = login(client, "viewer")
    assert client.post("/saved-views", headers=headers,
                       json={"name": "Wrong", "filters": {"severity": "supercritical"}}).status_code == 422
    assert client.post("/saved-views", headers=headers,
                       json={"name": "Wrong", "filters": {"user_id": "someone-else"}}).status_code == 422
    assert client.post("/saved-views", headers=headers, json={"name": " \t ", "filters": {}}).status_code == 422
    monkeypatch.setattr("app.workflows.MAX_SAVED_VIEWS", 1)
    assert client.post("/saved-views", headers=headers, json={"name": "First", "filters": {}}).status_code == 201
    assert client.post("/saved-views", headers=headers, json={"name": "Second", "filters": {}}).status_code == 422
    assert len(client.get("/saved-views").json()["results"]) == 1


def test_saved_view_quota_serializes_concurrent_creates(client, auth_headers, monkeypatch):
    from app import workflows
    from app.db import engine

    account(client, auth_headers, "viewer", "viewer")
    headers = login(client, "viewer")
    start = Barrier(2)
    second_count = Event()
    count_lock = Lock()
    count_calls = 0

    class ConcurrentSession(Session):
        def scalar(self, statement, *args, **kwargs):
            nonlocal count_calls
            result = super().scalar(statement, *args, **kwargs)
            if "count(" in str(statement) and "saved_views" in str(statement):
                with count_lock:
                    count_calls += 1
                    first = count_calls == 1
                if first:
                    # Give another transaction time to read the same pre-create
                    # count. With a write lock it waits until this create commits.
                    second_count.wait(timeout=0.5)
                else:
                    second_count.set()
            return result

    monkeypatch.setattr(workflows, "SessionLocal", sessionmaker(bind=engine, class_=ConcurrentSession, autoflush=False))
    monkeypatch.setattr(workflows, "MAX_SAVED_VIEWS", 1)

    def create(name):
        start.wait(timeout=5)
        return client.post("/saved-views", headers=headers, json={"name": name, "filters": {}}).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(create, ("First", "Second"))) == [201, 422]
    assert len(client.get("/saved-views").json()["results"]) == 1


def test_bulk_selection_is_atomic_and_viewers_cannot_write(client, auth_headers):
    first = signal(client, auth_headers, "Allowed one")
    second = signal(client, auth_headers, "Allowed two")
    private = signal(client, auth_headers, "Private", project="private")
    account(client, auth_headers, "analyst")
    account(client, auth_headers, "viewer", "viewer")
    headers = login(client, "analyst")
    response = client.post("/findings/bulk", headers=headers,
                           json={"ids": [first, private], "status": "resolved"})
    assert response.status_code == 404
    with SessionLocal() as db:
        assert db.get(Finding, first).status == "open"
        assert db.get(Finding, private).status == "open"
        assert db.scalar(select(func.count()).select_from(Comment)) == 0
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "findings.bulk_update")) == 0

    changed = client.post("/findings/bulk", headers=headers,
                          json={"ids": [second, first], "status": "investigating", "assignee": "analyst"})
    assert changed.status_code == 200, changed.text
    assert changed.json() == {"ok": True, "updated": 2}
    again = client.post("/findings/bulk", headers=headers,
                        json={"ids": [first, second], "status": "investigating", "assignee": "analyst"})
    assert again.json()["updated"] == 0
    with SessionLocal() as db:
        comments = db.scalars(select(Comment)).all()
        assert len(comments) == 2
        assert all(row.author == "analyst" and row.action_type == "update" for row in comments)
        assert db.get(Finding, private).status == "open"

    assert client.post("/findings/bulk", headers=headers,
                       json={"ids": [first], "assignee": None}).json()["updated"] == 1
    assert client.get(f"/findings/{first}").json()["assignee"] is None
    headers = login(client, "viewer")
    assert client.post("/findings/bulk", headers=headers, json={"ids": [first], "status": "closed"}).status_code == 403


@pytest.mark.parametrize("body", [
    {"ids": [], "status": "open"},
    {"ids": [str(uuid4()) for _ in range(201)], "status": "open"},
    {"ids": ["00000000-0000-4000-8000-000000000001"] * 2, "status": "open"},
    {"ids": [str(uuid4())]},
    {"ids": [str(uuid4())], "status": None},
    {"ids": [str(uuid4())], "project": "private", "status": "open"},
])
def test_bulk_rejects_ambiguous_or_unbounded_updates(client, auth_headers, body):
    assert client.post("/findings/bulk", headers=auth_headers, json=body).status_code == 422


def test_csv_matches_filtered_list_and_preserves_cell_boundaries(client, auth_headers):
    title = '=HYPERLINK("https://example.invalid", "Synthetic")\nnext, line'
    selected = signal(client, auth_headers, title, severity="critical")
    signal(client, auth_headers, "Different severity", severity="low")
    signal(client, auth_headers, "Private critical", project="private", severity="critical")
    account(client, auth_headers, "viewer", "viewer")
    login(client, "viewer")
    query = {"severity": "critical", "sort": "risk_desc"}
    listed = client.get("/findings", params=query).json()["results"]
    response = client.get("/findings/export.csv", params=query)
    rows = csv_rows(response)
    assert [row["id"] for row in rows] == [row["id"] for row in listed] == [selected]
    assert rows[0]["title"] == "[text] " + title
    assert rows[0]["project"] == "allowed"
    assert "description" not in rows[0] and "signal_id" not in rows[0]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"] == 'attachment; filename="secops-findings.csv"'
    assert response.headers["x-content-type-options"] == "nosniff"
    with SessionLocal() as db:
        event = db.scalar(select(AuditEvent).where(AuditEvent.action == "findings.export"))
        assert event.actor == "viewer"
        assert "Synthetic" not in event.details_json  # No finding evidence in download audit.


def test_csv_respects_empty_grants_and_treats_search_wildcards_as_text(client, auth_headers):
    selected = signal(client, auth_headers, "Literal 100%_ report")
    signal(client, auth_headers, "Literal 100zz report")
    account(client, auth_headers, "viewer", "viewer")
    account(client, auth_headers, "no-access", "viewer", projects=[])
    login(client, "viewer")
    query = {"q": "%_", "project": "allowed"}
    assert [row["id"] for row in csv_rows(client.get("/findings/export.csv", params=query))] == [selected]
    assert csv_rows(client.get("/findings/export.csv", params={"project": "private"})) == []
    login(client, "no-access")
    assert csv_rows(client.get("/findings/export.csv")) == []


@pytest.mark.parametrize("title", ["+1+2", "-1+2", "@SUM(1,2)", "  =1+2", "\t=1+2", "\r=1+2", "\n=1+2", "＝1+2", "＋1+2", "－1+2", "＠SUM(1,2)", "\u200b=1+2", " \u200b=1+2"])
def test_csv_marks_formula_like_text_without_executing_it(client, auth_headers, title):
    finding_id = signal(client, auth_headers, "Historical scanner value")
    # The manual signal endpoint trims surrounding whitespace. Historical or
    # scanner-imported values must still be handled safely by the exporter.
    with SessionLocal.begin() as db:
        db.get(Finding, finding_id).title = title
    rows = csv_rows(client.get("/findings/export.csv", headers=auth_headers))
    assert len(rows) == 1 and rows[0]["title"] == "[text] " + title


def test_csv_limits_fail_explicitly_without_truncated_success_or_audit(client, auth_headers, monkeypatch):
    for number in range(3):
        signal(client, auth_headers, f"Finding {number}")
    monkeypatch.setattr("app.workflows.MAX_EXPORT_ROWS", 2)
    response = client.get("/findings/export.csv", headers=auth_headers)
    assert response.status_code == 422 and "refine" in response.json()["detail"]
    assert "content-disposition" not in response.headers
    monkeypatch.setattr("app.workflows.MAX_EXPORT_ROWS", 10000)
    monkeypatch.setattr("app.workflows.MAX_EXPORT_BYTES", 64)
    response = client.get("/findings/export.csv", headers=auth_headers)
    assert response.status_code == 422
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "findings.export")) == 0


def test_workflow_cookie_writes_require_origin_and_scanner_key_has_no_new_privileges(client, auth_headers, ingest_headers):
    finding = signal(client, auth_headers)
    account(client, auth_headers, "analyst")
    login(client, "analyst")
    assert client.post("/saved-views", json={"name": "Missing origin", "filters": {}}).status_code == 403
    assert client.post("/findings/bulk", headers={"Origin": "https://untrusted.invalid"},
                       json={"ids": [finding], "status": "resolved"}).status_code == 403
    for path in ("/saved-views", "/findings/export.csv"):
        assert client.get(path, headers=ingest_headers).status_code == 401
    assert client.post("/findings/bulk", headers=ingest_headers,
                       json={"ids": [finding], "status": "resolved"}).status_code == 401
