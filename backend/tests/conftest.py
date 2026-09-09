from __future__ import annotations

import os
from pathlib import Path
import tempfile

import pytest
from fastapi.testclient import TestClient


TEST_DATABASE = Path(tempfile.gettempdir()) / f"secops-dashboard-tests-{os.getpid()}.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DATABASE}"
os.environ["API_KEY"] = "test-api-key"
os.environ["ALLOWED_HOSTS"] = "testserver,localhost,127.0.0.1"
os.environ.pop("ALLOW_INSECURE_NO_AUTH", None)

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers():
    return {"X-API-Key": "test-api-key"}


def pytest_sessionfinish(session, exitstatus):
    TEST_DATABASE.unlink(missing_ok=True)
