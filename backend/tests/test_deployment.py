from __future__ import annotations

import pytest

from app.db import get_database_url
from app.deployment import validate_backend_settings


@pytest.mark.parametrize("name,value", [
    ("API_KEY", ""),
    ("API_KEY", "too-short"),
    ("INGEST_API_KEY", "changeme-" + "0" * 32),
    ("MAX_FINDINGS_PER_IMPORT", "0"),
    ("MAX_SCAN_BYTES", "invalid"),
    ("NOTIFICATION_MAX_ATTEMPTS", "1000000"),
])
def test_invalid_deployment_configuration_is_rejected(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=name):
        validate_backend_settings()


def test_database_password_remains_literal_with_structured_settings(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("PGHOST", "database.invalid")
    password = "synthetic-password-with-@:/%?#"
    monkeypatch.setenv("PGPASSWORD", password)
    url = get_database_url()
    assert url.password == password
    assert url.host == "database.invalid"
    assert url.database == "secops"


def test_placeholder_database_password_is_rejected_without_exposure(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:changeme@database.invalid/db")
    with pytest.raises(ValueError, match="PostgreSQL password") as error:
        validate_backend_settings()
    assert "changeme" not in str(error.value)
