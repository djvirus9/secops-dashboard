from __future__ import annotations

import json

from sqlalchemy import select

from app.db import SessionLocal
from app.models import Signal


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


def test_scan_size_limit_is_enforced(client, auth_headers, monkeypatch):
    monkeypatch.setenv("MAX_SCAN_BYTES", "10")
    response = client.post(
        "/import/scan",
        headers=auth_headers,
        json={"content": "x" * 11, "parser": "generic-json"},
    )
    assert response.status_code == 413
