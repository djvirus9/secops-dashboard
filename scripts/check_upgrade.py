"""Rehearse 0.2 -> current schema on fresh synthetic SQLite, never an operator DB.

Run with the backend test dependencies installed. CI also checks PostgreSQL
migration parity through the backend suite.
"""
from datetime import UTC, datetime, timedelta
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import sqlalchemy as sa

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix="secops-upgrade-check-") as directory:
        database = Path(directory) / "synthetic.db"
        password = secrets.token_hex(24)
        bootstrap_password = secrets.token_hex(24)
        old_cookie = secrets.token_urlsafe(48)
        os.environ.update(DATABASE_URL=f"sqlite:///{database}", API_KEY=secrets.token_hex(32),
                          INGEST_API_KEY=secrets.token_hex(32), DASHBOARD_USERNAME="upgrade-admin",
                          DASHBOARD_PASSWORD=bootstrap_password, DASHBOARD_ORIGINS="http://localhost:5000",
                          SESSION_COOKIE_SECURE="false", SESSION_TTL_SECONDS="43200",
                          SESSION_IDLE_TIMEOUT_SECONDS="1800", ALLOWED_HOSTS="testserver,localhost,127.0.0.1",
                          ALLOW_INSECURE_NO_AUTH="false", ALLOW_UNVERIFIED_PARSERS="false", STORE_RAW_SCAN_DATA="false")
        for name in ("GITHUB_SYNC_TOKEN", "SLACK_WEBHOOK_URL", "JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"):
            os.environ[name] = ""

        def migrate(revision):
            subprocess.run([sys.executable, "-m", "alembic", "upgrade", revision], cwd=ROOT / "backend",
                           check=True, capture_output=True, text=True)

        migrate("0004")
        sys.path.insert(0, str(ROOT / "backend"))
        from argon2 import PasswordHasher
        from app.db import engine
        now = datetime.now(UTC).replace(tzinfo=None)
        legacy = sa.MetaData()
        legacy.reflect(bind=engine)
        user_id, asset_id, finding_id = "upgrade-user", "upgrade-asset", "upgrade-finding"
        with engine.begin() as connection:
            connection.execute(legacy.tables["users"].insert(), {
                "id": user_id, "username": "upgrade-admin", "password_hash": PasswordHasher().hash(password),
                "role": "admin", "projects_json": None, "active": True, "created_at": now, "updated_at": now,
            })
            connection.execute(legacy.tables["assets"].insert(), {
                "id": asset_id, "project": "upgrade-project", "key": "upgrade.example.invalid",
                "name": "", "environment": "unknown", "owner": "", "criticality": "medium",
                "exposure": "internal", "created_at": now, "updated_at": now,
            })
            connection.execute(legacy.tables["findings"].insert(), {
                "id": finding_id, "fingerprint": "a" * 64, "tool": "semgrep", "project": "upgrade-project",
                "source_id": None, "component": None, "component_version": None,
                "title": "Synthetic pre-upgrade finding", "severity": "high",
                "asset": "upgrade.example.invalid", "asset_id": asset_id, "exposure": "internal",
                "criticality": "medium", "status": "investigating", "assignee": "existing-analyst",
                "risk_score": 70, "occurrences": 7, "description": None, "recommendation": None,
                "cwe_id": None, "cve_id": None, "cvss_score": None, "file_path": None,
                "line_number": None, "references_json": "[]", "tags_json": "[]",
                "first_seen": now, "last_seen": now, "signal_id": "synthetic",
            })
            connection.execute(legacy.tables["comments"].insert(), {
                "id": "upgrade-comment", "finding_id": finding_id, "author": "upgrade-admin",
                "content": "Preserve historical triage", "action_type": None, "created_at": now,
            })
            connection.execute(legacy.tables["saved_views"].insert(), {
                "id": "upgrade-view", "user_id": user_id, "name": "Existing private view",
                "filters_json": '{"project":"upgrade-project"}', "created_at": now, "updated_at": now,
            })
            connection.execute(legacy.tables["user_sessions"].insert(), {
                "id": "upgrade-session", "user_id": user_id,
                "token_hash": hashlib.sha256(old_cookie.encode()).hexdigest(),
                "created_at": now, "last_seen_at": now, "expires_at": now + timedelta(hours=1),
                "revoked_at": None,
            })

        tables = ("assets", "findings", "comments", "users", "user_sessions", "saved_views")
        legacy_columns = {name: tuple(column.name for column in legacy.tables[name].columns) for name in tables}

        def snapshot():
            with sqlite3.connect(database) as db:
                return {
                    name: db.execute(
                        f'SELECT {", ".join(legacy_columns[name])} FROM "{name}" ORDER BY id'
                    ).fetchall()
                    for name in tables
                }

        before = snapshot()
        migrate("head")
        assert snapshot() == before, "Upgrade changed existing 0.2 records"
        from app.main import app
        from fastapi.testclient import TestClient
        with TestClient(app) as client:
            assert snapshot() == before, "Startup overwrote existing account or finding state"
            client.cookies.set("secops_session", old_cookie)
            assert client.get("/auth/me").status_code == 200, "Existing session did not survive upgrade"
            detail = client.get(f"/findings/{finding_id}")
            assert detail.status_code == 200
            value = detail.json()
            assert value["status"] == "investigating" and value["occurrences"] == 7
            assert len(value["comments"]) == 1
            assert client.get("/saved-views").json()["results"][0]["name"] == "Existing private view"
            assert client.get("/scanner-tokens").json()["count"] == 0
            assert client.get("/github-sync").json()["configured"] is False
            intelligence = client.get("/intelligence/status").json()["sources"]
            assert {row["source"] for row in intelligence} == {"cisa_kev", "first_epss"}
            assert value["priority_score"] == 30 and value["remediation_due_at"] is not None
            client.cookies.clear()
            assert client.post("/auth/login", headers={"Origin": "http://localhost:5000"},
                               json={"username": "upgrade-admin", "password": bootstrap_password}).status_code == 401
            assert client.post("/auth/login", headers={"Origin": "http://localhost:5000"},
                               json={"username": "upgrade-admin", "password": password}).status_code == 200
        engine.dispose()
    print("Synthetic 0.2 upgrade preserved workflow data and added explainable priority, SLA and intelligence state")


if __name__ == "__main__":
    main()
