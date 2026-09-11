from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from app.db import SessionLocal
from app.models import Signal
from app.parsers.base import ParsedFinding, Severity
from sqlalchemy import select


def test_invalid_signal_values_are_rejected(client, auth_headers):
    response = client.post(
        "/ingest/signal",
        headers=auth_headers,
        json={
            "tool": "nuclei",
            "severity": "urgent",
            "title": "Invalid severity",
            "exposure": "public-ish",
            "criticality": "highest",
        },
    )
    assert response.status_code == 422


def test_resurfaced_finding_is_reopened(client, auth_headers):
    payload = {
        "tool": "nuclei",
        "severity": "high",
        "title": "Recurring finding",
        "asset": "api.example.com",
        "exposure": "internet",
        "criticality": "high",
    }
    first = client.post("/ingest/signal", headers=auth_headers, json=payload).json()
    finding_id = first["finding_id"]

    resolved = client.patch(
        f"/findings/{finding_id}",
        headers=auth_headers,
        json={"status": "resolved"},
    )
    assert resolved.status_code == 200

    second = client.post("/ingest/signal", headers=auth_headers, json=payload).json()
    finding = client.get(f"/findings/{finding_id}", headers=auth_headers).json()
    assert second["deduped"] is True
    assert second["occurrences"] == 2
    assert finding["status"] == "open"
    assert any(comment["action_type"] == "reopened" for comment in finding["comments"])


def test_comment_author_comes_from_authenticated_identity(client, auth_headers):
    created = client.post(
        "/ingest/signal",
        headers=auth_headers,
        json={
            "tool": "nuclei",
            "severity": "low",
            "title": "Comment identity test",
            "asset": "comments.example.test",
        },
    ).json()
    headers = {**auth_headers, "X-SecOps-User": "dashboard-admin"}

    response = client.post(
        f"/findings/{created['finding_id']}/comments",
        headers=headers,
        json={"content": "Verified by the dashboard user"},
    )

    assert response.status_code == 200
    assert response.json()["comment"]["author"] == "api-admin"
    spoofed = client.post(
        f"/findings/{created['finding_id']}/comments",
        headers=headers,
        json={"author": "someone-else", "content": "Spoofed identity"},
    )
    assert spoofed.status_code == 422


def test_import_preserves_locations_but_omits_raw_scanner_data(client, auth_headers):
    content = json.dumps(
        {
            "findings": [
                {
                    "id": "RULE-1",
                    "title": "Unsafe call",
                    "severity": "high",
                    "asset": "service-a",
                    "file": "src/first.py",
                    "line": 10,
                    "references": ["https://example.test/rule-1"],
                    "secret": "must-not-be-stored",
                },
                {
                    "id": "RULE-1",
                    "title": "Unsafe call",
                    "severity": "high",
                    "asset": "service-a",
                    "file": "src/second.py",
                    "line": 20,
                },
            ]
        }
    )
    response = client.post(
        "/import/scan",
        headers=auth_headers,
        json={"content": content, "parser": "generic-json"},
    )
    assert response.status_code == 200
    assert response.json()["new_findings"] == 2

    findings = client.get("/findings", headers=auth_headers).json()["results"]
    assert {finding["file_path"] for finding in findings} == {
        "src/first.py",
        "src/second.py",
    }
    assert findings[0]["references"] or findings[1]["references"]

    with SessionLocal() as db:
        payloads = [json.loads(value) for value in db.scalars(select(Signal.payload))]
    assert all("raw_data" not in payload for payload in payloads)
    assert "must-not-be-stored" not in json.dumps(payloads)


def test_secret_scanner_values_are_redacted_everywhere(client, auth_headers, monkeypatch):
    monkeypatch.setenv("ALLOW_UNVERIFIED_PARSERS", "true")
    sentinel = "FAKE-LIVE-SECRET-123456789"
    content = json.dumps(
        [
            {
                "rule": {"message": "AWS credential", "severity": "Critical"},
                "path": "src/settings.py",
                "line": 12,
                "secret": sentinel,
                "context": {"line": f"AWS_SECRET={sentinel}"},
            }
        ]
    )

    response = client.post(
        "/import/scan",
        headers=auth_headers,
        json={"content": content, "parser": "trufflehog3"},
    )

    assert response.status_code == 200
    findings = client.get("/findings", headers=auth_headers).json()["results"]
    assert len(findings) == 1
    assert sentinel not in json.dumps(findings)
    assert "redacted before storage" in findings[0]["description"]
    with SessionLocal() as db:
        payloads = list(db.scalars(select(Signal.payload)))
    assert sentinel not in "".join(payloads)


def test_scan_size_limit_is_enforced(client, auth_headers, monkeypatch):
    monkeypatch.setenv("MAX_SCAN_BYTES", "10")
    response = client.post(
        "/import/scan",
        headers=auth_headers,
        json={"content": "x" * 11, "parser": "generic-json"},
    )
    assert response.status_code == 413


def test_raw_import_request_limit_is_enforced_before_validation(
    client, auth_headers, monkeypatch
):
    monkeypatch.setenv("MAX_IMPORT_REQUEST_BYTES", "100")
    response = client.post(
        "/import/scan",
        headers=auth_headers,
        json={"content": "x" * 200, "parser": "generic-json"},
    )
    assert response.status_code == 413


def test_chunked_import_request_limit_is_enforced(client, auth_headers, monkeypatch):
    monkeypatch.setenv("MAX_IMPORT_REQUEST_BYTES", "100")

    def chunks():
        yield b'{"content":"'
        yield b"x" * 200
        yield b'","parser":"generic-json"}'

    response = client.post(
        "/import/scan",
        headers={**auth_headers, "Content-Type": "application/json"},
        content=chunks(),
    )
    assert response.status_code == 413


def test_parsed_finding_count_limit_is_enforced(
    client, auth_headers, monkeypatch
):
    from app import main as main_module

    monkeypatch.setenv("MAX_FINDINGS_PER_IMPORT", "1")
    monkeypatch.setattr(
        main_module,
        "parse_scan_results",
        lambda **kwargs: [
            ParsedFinding(title="One", severity=Severity.LOW, tool="generic-json"),
            ParsedFinding(title="Two", severity=Severity.LOW, tool="generic-json"),
        ],
    )
    response = client.post(
        "/import/scan",
        headers=auth_headers,
        json={"content": "{}", "parser": "generic-json"},
    )
    assert response.status_code == 413


def test_lower_risk_recurrence_preserves_matching_risk_dimensions(client, auth_headers):
    base = {
        "tool": "nuclei",
        "title": "Risk consistency test",
        "asset": "risk.example.test",
    }
    first = client.post(
        "/ingest/signal",
        headers=auth_headers,
        json={
            **base,
            "severity": "critical",
            "exposure": "internet",
            "criticality": "high",
        },
    ).json()
    second = client.post(
        "/ingest/signal",
        headers=auth_headers,
        json={
            **base,
            "severity": "low",
            "exposure": "internal",
            "criticality": "low",
        },
    ).json()
    finding = client.get(
        f"/findings/{first['finding_id']}", headers=auth_headers
    ).json()

    assert second["occurrences"] == 2
    assert finding["severity"] == "critical"
    assert finding["exposure"] == "internet"
    assert finding["criticality"] == "high"
    assert finding["risk_score"] == first["risk_score"]


def test_concurrent_identical_signals_increment_atomically(client, auth_headers):
    payload = {
        "tool": "nuclei",
        "severity": "medium",
        "title": "Concurrent scanner finding",
        "asset": "concurrent.example.test",
    }

    def ingest(_):
        return client.post("/ingest/signal", headers=auth_headers, json=payload)

    with ThreadPoolExecutor(max_workers=4) as executor:
        responses = list(executor.map(ingest, range(8)))

    assert all(response.status_code == 200 for response in responses)
    findings = client.get("/findings", headers=auth_headers).json()["results"]
    assert len(findings) == 1
    assert findings[0]["occurrences"] == 8
