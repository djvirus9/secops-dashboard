from __future__ import annotations

from datetime import timedelta
import json

import pytest
from sqlalchemy import select

from app.db import SessionLocal
from app.models import AuditEvent, Finding, IntelligenceSyncState, RemediationPolicy, _utcnow
from app.remediation import client as intelligence_client
from app.remediation import service


ORIGIN = "http://localhost:5000"
PASSWORD = "synthetic-password-123"


@pytest.fixture(autouse=True)
def session_settings(monkeypatch):
    monkeypatch.setenv("DASHBOARD_ORIGINS", ORIGIN)
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")


def create_user(client, headers, username: str, role: str):
    response = client.post("/users", headers=headers, json={
        "username": username, "password": PASSWORD, "role": role, "projects": None,
    })
    assert response.status_code == 201, response.text


def login(client, username: str):
    response = client.post("/auth/login", headers={"Origin": ORIGIN}, json={
        "username": username, "password": PASSWORD,
    })
    assert response.status_code == 200, response.text
    client.headers["Origin"] = ORIGIN


def import_cve(client, headers, *, project="payments", cve="CVE-2026-12345"):
    response = client.post("/import/scan", headers=headers, json={
        "project": project,
        "parser": "generic-json",
        "default_exposure": "internet",
        "default_criticality": "high",
        "content": json.dumps([{
            "id": "fixture-cve", "title": "Synthetic vulnerable dependency",
            "severity": "high", "asset": "api.example.invalid", "cve": cve,
        }]),
    })
    assert response.status_code == 200, response.text
    return client.get("/findings", headers=headers).json()["results"][0]


def test_priority_is_explainable_and_sla_is_assigned_on_ingest(client, auth_headers):
    finding = import_cve(client, auth_headers)

    assert finding["priority_score"] == 55
    assert finding["sla_status"] in {"on_track", "due_soon"}
    assert finding["remediation_due_at"] is not None
    assert finding["kev"] is False and finding["epss_score"] is None
    assert finding["priority_reasons"] == [
        {"factor": "High severity", "points": 30},
        {"factor": "Internet exposed", "points": 15},
        {"factor": "High-criticality asset", "points": 10},
    ]


def test_fixed_feed_sync_enriches_findings_and_recalculates_priority(
    client, auth_headers, monkeypatch,
):
    finding = import_cve(client, auth_headers)
    monkeypatch.setattr(intelligence_client, "fetch_kev", lambda: [{
        "cve_id": "CVE-2026-12345", "kev_date_added": _utcnow().date(),
        "kev_due_date": (_utcnow() + timedelta(days=14)).date(),
        "kev_ransomware": True, "kev_required_action": "Apply the synthetic update.",
    }])
    monkeypatch.setattr(intelligence_client, "fetch_epss", lambda cves: [{
        "cve_id": "CVE-2026-12345", "epss_score": 0.82, "epss_percentile": 0.97,
    }])

    queued = client.post("/intelligence/sync", headers=auth_headers, json={
        "sources": ["cisa_kev", "first_epss"],
    })
    assert queued.status_code == 202
    assert service.process_one() is True
    assert service.process_one() is True
    assert service.process_one() is False

    enriched = client.get(f"/findings/{finding['id']}", headers=auth_headers).json()
    assert enriched["kev"] is True
    assert enriched["kev_ransomware"] is True
    assert enriched["epss_score"] == 0.82
    assert enriched["epss_percentile"] == 0.97
    assert enriched["priority_score"] == 95
    assert enriched["remediation_due_at"][:10] == (
        _utcnow() + timedelta(days=7)
    ).date().isoformat()
    states = client.get("/intelligence/status", headers=auth_headers).json()["sources"]
    assert {row["status"] for row in states} == {"succeeded"}
    assert {row["record_count"] for row in states} == {1}


def test_feed_failure_preserves_last_successful_intelligence(client, auth_headers, monkeypatch):
    finding = import_cve(client, auth_headers)
    monkeypatch.setattr(intelligence_client, "fetch_kev", lambda: [{
        "cve_id": "CVE-2026-12345", "kev_date_added": _utcnow().date(),
        "kev_due_date": (_utcnow() + timedelta(days=14)).date(),
        "kev_ransomware": False, "kev_required_action": "Apply the synthetic update.",
    }])
    client.post("/intelligence/sync", headers=auth_headers, json={"sources": ["cisa_kev"]})
    service.process_one()
    monkeypatch.setattr(
        intelligence_client, "fetch_kev",
        lambda: (_ for _ in ()).throw(intelligence_client.IntelligenceFetchError("Synthetic outage")),
    )
    client.post("/intelligence/sync", headers=auth_headers, json={"sources": ["cisa_kev"]})
    service.process_one()

    preserved = client.get(f"/findings/{finding['id']}", headers=auth_headers).json()
    assert preserved["kev"] is True
    state = client.get("/intelligence/status", headers=auth_headers).json()["sources"][0]
    assert state["source"] == "cisa_kev" and state["status"] == "failed"
    assert state["record_count"] == 1


def test_successful_epss_refresh_clears_a_removed_record(client, auth_headers, monkeypatch):
    finding = import_cve(client, auth_headers)
    monkeypatch.setattr(intelligence_client, "fetch_epss", lambda cves: [{
        "cve_id": "CVE-2026-12345", "epss_score": 0.82, "epss_percentile": 0.97,
    }])
    client.post("/intelligence/sync", headers=auth_headers, json={"sources": ["first_epss"]})
    service.process_one()
    assert client.get(f"/findings/{finding['id']}", headers=auth_headers).json()["epss_score"] == 0.82

    monkeypatch.setattr(intelligence_client, "fetch_epss", lambda cves: [])
    client.post("/intelligence/sync", headers=auth_headers, json={"sources": ["first_epss"]})
    service.process_one()
    refreshed = client.get(f"/findings/{finding['id']}", headers=auth_headers).json()
    assert refreshed["epss_score"] is None
    assert refreshed["epss_percentile"] is None
    assert refreshed["priority_score"] == 55


def test_disabling_a_source_cancels_queued_work(client, auth_headers, monkeypatch):
    monkeypatch.setattr(intelligence_client, "fetch_kev", lambda: pytest.fail("Disabled source must not run"))
    client.post("/intelligence/sync", headers=auth_headers, json={"sources": ["cisa_kev"]})
    changed = client.put("/intelligence/status/cisa_kev", headers=auth_headers, json={
        "enabled": False, "interval_hours": 24,
    })
    assert changed.status_code == 200
    assert service.process_one() is False
    state = client.get("/intelligence/status", headers=auth_headers).json()["sources"][0]
    assert state["source"] == "cisa_kev" and state["status"] == "idle"


def test_disabling_a_source_fences_an_in_progress_refresh(client, auth_headers):
    client.post("/intelligence/sync", headers=auth_headers, json={"sources": ["cisa_kev"]})
    task = service.claim_sync()
    assert task is not None and task["source"] == "cisa_kev"

    changed = client.put("/intelligence/status/cisa_kev", headers=auth_headers, json={
        "enabled": False, "interval_hours": 24,
    })
    assert changed.status_code == 200
    assert service.apply_feed(task, [{
        "cve_id": "CVE-2026-12345", "kev_date_added": _utcnow().date(),
        "kev_due_date": (_utcnow() + timedelta(days=14)).date(),
        "kev_ransomware": False, "kev_required_action": "Apply the synthetic update.",
    }]) is False
    state = client.get("/intelligence/status", headers=auth_headers).json()["sources"][0]
    assert state["source"] == "cisa_kev" and state["status"] == "idle"


def test_project_policy_recalculates_existing_deadlines_and_is_audited(client, auth_headers):
    finding = import_cve(client, auth_headers)
    response = client.put("/remediation/policies", headers=auth_headers, json={
        "project": "payments", "critical_days": 1, "high_days": 2,
        "medium_days": 3, "low_days": 4, "info_days": 5, "kev_days": 1,
    })
    assert response.status_code == 200, response.text
    assert response.json()["affected_findings"] == 1
    changed = client.get(f"/findings/{finding['id']}", headers=auth_headers).json()
    assert changed["remediation_due_at"][:10] == (
        _utcnow() + timedelta(days=2)
    ).date().isoformat()
    with SessionLocal() as db:
        assert db.get(RemediationPolicy, "payments").high_days == 2
        event = db.scalar(select(AuditEvent).where(AuditEvent.action == "remediation_policy.create"))
        assert json.loads(event.details_json)["affected_findings"] == 1

    normalized = client.put("/remediation/policies", headers=auth_headers, json={
        "project": "  payments  ", "critical_days": 1, "high_days": 2,
        "medium_days": 3, "low_days": 4, "info_days": 5, "kev_days": 1,
    })
    assert normalized.status_code == 200
    assert normalized.json()["policy"]["project"] == "payments"
    assert client.put("/remediation/policies", headers=auth_headers, json={
        "project": "bad\u0000project",
    }).status_code == 422


def test_risk_acceptance_requires_an_admin_session_and_expires(client, auth_headers):
    finding = import_cve(client, auth_headers)
    body = {"reason": "Temporary vendor dependency with a documented compensating control.",
            "expires_at": (_utcnow() + timedelta(days=30)).isoformat() + "Z"}
    assert client.post(
        f"/findings/{finding['id']}/risk-acceptance", headers=auth_headers, json=body,
    ).status_code == 403

    create_user(client, auth_headers, "analyst", "analyst")
    login(client, "analyst")
    assert client.post(f"/findings/{finding['id']}/risk-acceptance", json=body).status_code == 403

    client.cookies.clear()
    client.headers.pop("Origin", None)
    create_user(client, auth_headers, "risk-owner", "admin")
    login(client, "risk-owner")
    accepted = client.post(f"/findings/{finding['id']}/risk-acceptance", json=body)
    assert accepted.status_code == 200, accepted.text
    result = client.get(f"/findings/{finding['id']}").json()
    assert result["risk_acceptance"]["status"] == "active"
    assert result["risk_acceptance"]["accepted_by"] == "risk-owner"
    assert result["priority_score"] == finding["priority_score"]
    summary = client.get("/dashboard/summary").json()
    assert summary["sla"] == {
        "tracked": 1, "overdue": 0, "accepted": 1, "on_track": 0, "compliance_percent": 100,
    }
    assert summary["priority_buckets"]["elevated"] == 1
    assert summary["top_assets"][0]["max_priority"] == finding["priority_score"]
    assert summary["trend"][-1]["new"] == 1
    assert client.delete(f"/findings/{finding['id']}/risk-acceptance").status_code == 204
    assert client.get(f"/findings/{finding['id']}").json()["risk_acceptance"]["status"] == "none"


@pytest.mark.parametrize("value", [
    "CVE-1", "not-a-cve", "CVE-2026-1/../../metadata", "CVE-2026-12345678901234567890", 7, None,
])
def test_cve_normalization_fails_closed(value):
    assert intelligence_client.normalize_cve(value) is None


@pytest.mark.parametrize("response", [
    {"redirect": True, "headers": {"content-type": "application/json"}, "content": b"{}", "limit": intelligence_client.MAX_KEV_BYTES},
    {"redirect": False, "headers": {"content-type": "application/json", "content-length": str(9 * 1024 * 1024)}, "content": b"{}", "limit": intelligence_client.MAX_KEV_BYTES},
    {"redirect": False, "headers": {"content-type": "application/json"}, "content": b"{}", "limit": 1},
])
def test_feed_transport_rejects_redirects_and_oversized_documents(monkeypatch, response):
    class FakeResponse:
        is_redirect = response["redirect"]
        headers = response["headers"]

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def raise_for_status(self):
            return None

        def iter_bytes(self):
            yield response["content"]

    class FakeClient:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def __enter__(self):
            assert self.kwargs["follow_redirects"] is False
            assert self.kwargs["trust_env"] is False
            return self

        def __exit__(self, *_):
            return None

        def stream(self, method, url, params=None):
            assert method == "GET"
            assert url == intelligence_client.CISA_KEV_URL
            return FakeResponse()

    monkeypatch.setattr(intelligence_client.httpx, "Client", FakeClient)
    with pytest.raises(intelligence_client.IntelligenceFetchError):
        intelligence_client._json_response(
            intelligence_client.CISA_KEV_URL, limit=response["limit"],
        )


def test_feed_documents_reject_empty_kev_and_unrequested_epss_records(monkeypatch):
    monkeypatch.setattr(intelligence_client, "_json_response", lambda *args, **kwargs: {
        "vulnerabilities": [],
    })
    with pytest.raises(intelligence_client.IntelligenceFetchError):
        intelligence_client.fetch_kev()

    monkeypatch.setattr(intelligence_client, "_json_response", lambda *args, **kwargs: {
        "data": [{"cve": "CVE-2026-99999", "epss": "0.5", "percentile": "0.9"}],
    })
    with pytest.raises(intelligence_client.IntelligenceFetchError):
        intelligence_client.fetch_epss(["CVE-2026-12345"])
