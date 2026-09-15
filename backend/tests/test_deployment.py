from __future__ import annotations

import pytest

from app.db import get_database_url
from app.deployment import validate_backend_settings, validate_session_settings, validate_worker_settings


@pytest.mark.parametrize("name,value", [
    ("API_KEY", ""),
    ("API_KEY", "too-short"),
    ("INGEST_API_KEY", "changeme-" + "0" * 32),
    ("MAX_FINDINGS_PER_IMPORT", "0"),
    ("MAX_SCAN_BYTES", "invalid"),
    ("NOTIFICATION_MAX_ATTEMPTS", "1000000"),
    ("SESSION_TTL_SECONDS", "299"),
    ("SESSION_TTL_SECONDS", "604801"),
    ("SESSION_IDLE_TIMEOUT_SECONDS", "59"),
    ("SESSION_IDLE_TIMEOUT_SECONDS", "86401"),
    ("GITHUB_SYNC_POLL_SECONDS", "0"),
    ("GITHUB_SYNC_POLL_SECONDS", "301"),
    ("GITHUB_SYNC_TOKEN", "short"),
    ("GITHUB_SYNC_TOKEN", "x" * 513),
    ("GITHUB_SYNC_TOKEN", "x" * 32 + "\n"),
    ("GITHUB_SYNC_TOKEN", "é" * 32),
    ("AUTOMATION_POLL_SECONDS", "0"),
    ("AUTOMATION_POLL_SECONDS", "301"),
    ("JIRA_SYNC_INTERVAL_MINUTES", "14"),
    ("JIRA_SYNC_INTERVAL_MINUTES", "1441"),
    ("JIRA_SYNC_ENABLED", "maybe"),
    ("JIRA_SYNC_ENABLED", "true"),
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


def test_intelligence_worker_does_not_require_unrelated_credentials(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("INGEST_API_KEY", raising=False)
    monkeypatch.setenv("GITHUB_SYNC_TOKEN", "invalid-but-unrelated")
    validate_worker_settings("intelligence")
    monkeypatch.setenv("INTELLIGENCE_POLL_SECONDS", "301")
    with pytest.raises(ValueError, match="INTELLIGENCE_POLL_SECONDS"):
        validate_worker_settings("intelligence")


def test_github_worker_still_validates_its_own_token(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("GITHUB_SYNC_TOKEN", "too-short")
    with pytest.raises(ValueError, match="GITHUB_SYNC_TOKEN"):
        validate_worker_settings("github")


def test_placeholder_database_password_is_rejected_without_exposure(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:changeme@database.invalid/db")
    with pytest.raises(ValueError, match="PostgreSQL password") as error:
        validate_backend_settings()
    assert "changeme" not in str(error.value)


def test_automation_worker_validates_only_its_own_credentials(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("INGEST_API_KEY", raising=False)
    monkeypatch.setenv("GITHUB_SYNC_TOKEN", "invalid-but-unrelated")
    validate_worker_settings("automation")
    monkeypatch.setenv("JIRA_SYNC_ENABLED", "true")
    with pytest.raises(ValueError, match="JIRA_SYNC_ENABLED"):
        validate_worker_settings("automation")
    monkeypatch.setenv("JIRA_BASE_URL", "https://synthetic.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "synthetic@example.invalid")
    monkeypatch.setenv("JIRA_API_TOKEN", "synthetic-local-test-token")
    validate_worker_settings("automation")


@pytest.fixture
def clean_session_config(monkeypatch):
    for name in ("DASHBOARD_USERNAME", "DASHBOARD_PASSWORD", "DASHBOARD_ORIGINS",
                 "SESSION_COOKIE_SECURE", "SESSION_TTL_SECONDS", "SESSION_IDLE_TIMEOUT_SECONDS"):
        monkeypatch.delenv(name, raising=False)


def test_session_idle_timeout_cannot_exceed_absolute_lifetime(monkeypatch, clean_session_config):
    monkeypatch.setenv("SESSION_TTL_SECONDS", "300")
    monkeypatch.setenv("SESSION_IDLE_TIMEOUT_SECONDS", "301")
    with pytest.raises(ValueError, match="must not exceed"):
        validate_backend_settings()


@pytest.mark.parametrize("origin", ["http://localhost:5000", "http://127.0.0.1:5050", "http://[::1]:5000",
                                    "http://127.0.0.1:5050,http://localhost:5050"])
def test_insecure_session_cookie_only_accepts_strict_loopback_origins(monkeypatch, clean_session_config, origin):
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("DASHBOARD_ORIGINS", origin)
    validate_session_settings()


@pytest.mark.parametrize("origin", ["http://dashboard.example.com", "http://localhost.example.com", "http://127.0.0.2",
                                    "http://0.0.0.0:5000", "https://localhost:5000",
                                    "http://localhost:5000,https://dashboard.example.com"])
def test_insecure_session_cookie_rejects_nonlocal_configuration(monkeypatch, clean_session_config, origin):
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("DASHBOARD_ORIGINS", origin)
    with pytest.raises(ValueError, match="strict loopback"):
        validate_session_settings()


@pytest.mark.parametrize("origin", ["", "null", "*", "https://*.example.com", "https://example.com/", "https://example.com:443",
                                    "https://example.com/path", "https://example.com?query=1", "https://user:secret@example.com",
                                    "https://EXAMPLE.com", "http://localhost:0", "https://example.com,", "https://example.com\\evil"])
def test_session_origins_require_exact_canonical_values(monkeypatch, clean_session_config, origin):
    monkeypatch.setenv("DASHBOARD_ORIGINS", origin)
    with pytest.raises(ValueError, match="canonical"):
        validate_session_settings()


def test_bootstrap_configuration_can_be_omitted_for_api_only_mode(monkeypatch, clean_session_config):
    validate_session_settings()
    monkeypatch.setenv("DASHBOARD_USERNAME", "admin")
    with pytest.raises(ValueError, match="supplied together"):
        validate_session_settings()
    monkeypatch.setenv("DASHBOARD_PASSWORD", "synthetic-bootstrap-password")
    validate_session_settings()
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "maybe")
    with pytest.raises(ValueError, match="boolean"):
        validate_session_settings()


def test_bootstrap_password_preserves_the_24_character_minimum(monkeypatch, clean_session_config):
    monkeypatch.setenv("DASHBOARD_USERNAME", "admin")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "B" * 23)
    with pytest.raises(ValueError, match="DASHBOARD_PASSWORD.*24"):
        validate_session_settings()
    monkeypatch.setenv("DASHBOARD_PASSWORD", "B" * 24)
    validate_session_settings()
