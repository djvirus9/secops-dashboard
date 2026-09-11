"""Fail early on invalid deployment configuration without logging secret values."""
from __future__ import annotations

import os
import sys
from urllib.parse import urlsplit


TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


def validate_session_settings() -> None:
    secure = os.environ.get("SESSION_COOKIE_SECURE", "true").strip().lower()
    if secure not in TRUE_VALUES | FALSE_VALUES:
        raise ValueError("SESSION_COOKIE_SECURE must be a boolean")
    origins = os.environ.get("DASHBOARD_ORIGINS", "http://localhost:5000").split(",")
    if not origins or any(not value.strip() for value in origins):
        raise ValueError("DASHBOARD_ORIGINS must contain canonical browser origins")
    for value in origins:
        origin = value.strip()
        try:
            parsed = urlsplit(origin)
            port = parsed.port
            host = parsed.hostname
            if (not host or not host.isascii() or any(char in host for char in "\\%* \t\r\n")
                    or parsed.scheme not in {"http", "https"} or port == 0):
                raise ValueError
            authority = f"[{host}]" if ":" in host else host
            if port is not None and port != (443 if parsed.scheme == "https" else 80):
                authority += f":{port}"
            canonical = f"{parsed.scheme}://{authority}"
            if origin != canonical or parsed.username is not None or parsed.password is not None:
                raise ValueError
        except ValueError as exc:
            raise ValueError("DASHBOARD_ORIGINS must contain canonical browser origins") from exc
        if secure in FALSE_VALUES and (parsed.scheme != "http" or host not in {"localhost", "127.0.0.1", "::1"}):
            raise ValueError("SESSION_COOKIE_SECURE=false requires only strict loopback HTTP origins")

    username = os.environ.get("DASHBOARD_USERNAME", "")
    password = os.environ.get("DASHBOARD_PASSWORD", "")
    if bool(username) != bool(password):
        raise ValueError("DASHBOARD_USERNAME and DASHBOARD_PASSWORD must be supplied together")
    if username:
        from app.accounts import normalize_username, validate_password
        normalize_username(username)
        validate_password(password)
        _require_secret("DASHBOARD_PASSWORD", 24, password)


def _require_secret(name: str, minimum: int, value: str | None = None) -> None:
    if value is None:
        value = os.environ.get(name, "")
    if (
        len(value) < minimum
        or value != value.strip()
        or any(marker in value.lower() for marker in ("changeme", "change-me", "example", "replace-me"))
    ):
        raise ValueError(f"{name} must be a non-placeholder secret of at least {minimum} characters")


def validate_backend_settings() -> None:
    github_token = os.environ.get("GITHUB_SYNC_TOKEN", "")
    if github_token and (not 32 <= len(github_token) <= 512 or not github_token.isascii()
                         or any(ord(char) < 33 or ord(char) > 126 for char in github_token)):
        raise ValueError("GITHUB_SYNC_TOKEN must be 32–512 printable ASCII characters without whitespace")
    if os.environ.get("ALLOW_INSECURE_NO_AUTH", "").lower() not in TRUE_VALUES:
        _require_secret("API_KEY", 32)
        _require_secret("INGEST_API_KEY", 32)
        if os.environ["API_KEY"] == os.environ["INGEST_API_KEY"]:
            raise ValueError("API_KEY and INGEST_API_KEY must be different")
    from app.db import get_database_url
    database_url = get_database_url()
    if database_url.get_backend_name() == "postgresql":
        _require_secret("PostgreSQL password", 24, database_url.password or "")

    limits = {
        "MAX_REQUEST_BYTES": (1048576, 1, 10485760),
        "MAX_SCAN_BYTES": (10485760, 1, 104857600),
        "MAX_IMPORT_REQUEST_BYTES": (12582912, 1, 134217728),
        "MAX_FINDINGS_PER_IMPORT": (10000, 1, 100000),
        "IMPORT_TIMEOUT_SECONDS": (900, 1, 3600),
        "NOTIFICATION_POLL_SECONDS": (5, 1, 300),
        "GITHUB_SYNC_POLL_SECONDS": (5, 1, 300),
        "NOTIFICATION_MAX_ATTEMPTS": (5, 1, 20),
        "SESSION_TTL_SECONDS": (43200, 300, 604800),
        "SESSION_IDLE_TIMEOUT_SECONDS": (1800, 60, 86400),
    }
    for name, (default, minimum, maximum) in limits.items():
        try:
            value = int(os.environ.get(name, str(default)))
        except ValueError as exc:
            raise ValueError(f"{name} must be an integer") from exc
        if not minimum <= value <= maximum:
            raise ValueError(f"{name} must be between {minimum} and {maximum}")
    if int(os.environ.get("SESSION_IDLE_TIMEOUT_SECONDS", "1800")) > int(os.environ.get("SESSION_TTL_SECONDS", "43200")):
        raise ValueError("SESSION_IDLE_TIMEOUT_SECONDS must not exceed SESSION_TTL_SECONDS")
    validate_session_settings()


def main() -> int:
    try:
        validate_backend_settings()
    except ValueError as exc:
        print(f"Invalid deployment configuration: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
