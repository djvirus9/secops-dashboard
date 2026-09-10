"""Fail early on invalid deployment configuration without logging secret values."""
from __future__ import annotations

import os
import sys


TRUE_VALUES = {"1", "true", "yes", "on"}


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
        "NOTIFICATION_MAX_ATTEMPTS": (5, 1, 20),
    }
    for name, (default, minimum, maximum) in limits.items():
        try:
            value = int(os.environ.get(name, str(default)))
        except ValueError as exc:
            raise ValueError(f"{name} must be an integer") from exc
        if not minimum <= value <= maximum:
            raise ValueError(f"{name} must be between {minimum} and {maximum}")


def main() -> int:
    try:
        validate_backend_settings()
    except ValueError as exc:
        print(f"Invalid deployment configuration: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
