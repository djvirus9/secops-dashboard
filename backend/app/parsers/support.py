"""Parser capabilities backed by the checked-in valid/clean/malformed fixtures.

Adding a name here enables it in production. Extend the fixture matrix and
schema validation before changing this set; registration alone is not support.
"""

import os


VERIFIED_PARSERS = frozenset({
    "generic-json", "generic-csv", "sarif", "semgrep", "bandit", "codeql",
    "trivy", "grype", "osv-scanner", "nuclei", "aws-security-hub", "aws_asff",
    "nessus", "credscan",
})


def allow_unverified_parsers() -> bool:
    return os.getenv("ALLOW_UNVERIFIED_PARSERS", "false").strip().lower() in {
        "true", "1", "yes", "on",
    }


def parser_availability(name: str) -> dict:
    verified = name in VERIFIED_PARSERS
    enabled = verified or allow_unverified_parsers()
    return {
        "verification_status": "verified" if verified else "unverified",
        "enabled": enabled,
        "unavailable_reason": None if enabled else (
            "Compatibility adapter has no verified fixture coverage. "
            "An operator must set ALLOW_UNVERIFIED_PARSERS=true to enable it."
        ),
    }
