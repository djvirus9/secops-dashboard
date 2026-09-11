from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from alembic import command
from alembic.config import Config

configured_database = os.environ.get("TEST_DATABASE_URL")
TEST_DATABASE = None
if configured_database:
    os.environ["DATABASE_URL"] = configured_database
else:
    TEST_DATABASE = Path(tempfile.gettempdir()) / f"secops-dashboard-tests-{os.getpid()}.db"
    os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DATABASE}"
TEST_ADMIN_KEY = "test-admin-key-000000000000000000000000000000"
TEST_INGEST_KEY = "test-ingest-key-00000000000000000000000000000"
os.environ["API_KEY"] = TEST_ADMIN_KEY
os.environ["INGEST_API_KEY"] = TEST_INGEST_KEY
os.environ["ALLOWED_HOSTS"] = "testserver,localhost,127.0.0.1"
os.environ.pop("ALLOW_INSECURE_NO_AUTH", None)
for name in (
    "SLACK_WEBHOOK_URL", "JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN",
    "JIRA_PROJECT_KEY", "ALLOW_UNVERIFIED_PARSERS", "STORE_RAW_SCAN_DATA",
    "DASHBOARD_USERNAME", "DASHBOARD_PASSWORD", "DASHBOARD_ORIGINS", "CORS_ORIGINS",
    "SESSION_COOKIE_SECURE", "SESSION_TTL_SECONDS", "SESSION_IDLE_TIMEOUT_SECONDS",
):
    os.environ.pop(name, None)

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def migrated_database():
    backend_root = Path(__file__).resolve().parents[1]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "migrations"))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    yield
    engine.dispose()


@pytest.fixture(autouse=True)
def clean_database(migrated_database):
    # Exercise the actual migrated schema throughout the suite. Only test rows
    # are removed; create_all must not silently mask missing migrations.
    def clear_rows():
        with engine.begin() as connection:
            for table in reversed(Base.metadata.sorted_tables):
                connection.execute(table.delete())
    clear_rows()
    yield
    clear_rows()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers():
    return {"X-API-Key": TEST_ADMIN_KEY}


@pytest.fixture
def ingest_headers():
    return {"X-API-Key": TEST_INGEST_KEY}


def pytest_sessionfinish(session, exitstatus):
    if TEST_DATABASE:
        TEST_DATABASE.unlink(missing_ok=True)
