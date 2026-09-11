import json

from sqlalchemy import func, select

from app.db import SessionLocal
from app.models import Asset, Finding, ImportRun, NotificationDelivery, Signal


def scan(client, headers, data, parser="generic-json", **options):
    return client.post("/import/scan", headers=headers,
                       json={"parser": parser, "content": json.dumps(data), **options})


def test_component_identity_survives_versions_and_distinct_packages(client, auth_headers):
    def report(version):
        return {"Results": [{"Target": "image", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2099-0001", "PkgName": package,
             "InstalledVersion": version, "FixedVersion": "3", "Severity": "HIGH"}
            for package in ("openssl", "libssl")]}]}
    response = scan(client, auth_headers, report("1"), "trivy", project="repo-a")
    assert response.status_code == 200, response.text
    assert response.json()["new_findings"] == 2
    response = scan(client, auth_headers, report("2"), "trivy", project="repo-a")
    assert response.json()["new_findings"] == 0
    assert response.json()["deduplicated"] == 2
    rows = client.get("/findings", headers=auth_headers).json()["results"]
    assert {row["component"] for row in rows} == {"openssl", "libssl"}
    assert all(row["occurrences"] == 2 and row["component_version"] == "2" for row in rows)


def test_same_relative_path_remains_separate_across_projects(client, auth_headers):
    report = {"results": [{"test_id": "B101", "test_name": "assert_used", "issue_severity": "HIGH",
                            "filename": "app.py", "line_number": 10}]}
    for project in ("repo-a", "repo-b"):
        response = scan(client, auth_headers, report, "bandit", project=project)
        assert response.json()["new_findings"] == 1
    rows = client.get("/findings", headers=auth_headers).json()["results"]
    assert len(rows) == 2 and len({row["asset_id"] for row in rows}) == 2
    assert {row["project"] for row in rows} == {"repo-a", "repo-b"}
    assert len(client.get("/risks", headers=auth_headers).json()["results"]) == 2


def test_legacy_default_asset_supplies_missing_asset_and_scope(client, auth_headers):
    for project in ("repo-a", "repo-b"):
        response = scan(client, auth_headers, [{"title": "Fallback", "severity": "low"}], default_asset=project)
        assert response.status_code == 200, response.text
    rows = client.get("/findings", headers=auth_headers).json()["results"]
    assert {(row["asset"], row["project"]) for row in rows} == {("repo-a", "repo-a"), ("repo-b", "repo-b")}


def test_duplicate_rows_refresh_counts_and_queue_one_event_per_channel(client, auth_headers, monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://slack.invalid/webhook")
    for key in ("JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"):
        monkeypatch.setenv(key, "synthetic-test-value")
    item = {"title": "Duplicate", "severity": "high", "id": "RULE", "asset": "same"}
    response = scan(client, auth_headers, [item] * 3)
    assert response.status_code == 200, response.text
    assert response.json()["new_findings"] == 1
    assert response.json()["deduplicated"] == 2
    with SessionLocal() as db:
        deliveries = db.scalars(select(NotificationDelivery)).all()
        assert len(deliveries) == 2
        assert {row.channel for row in deliveries} == {"slack", "jira"}
        assert all(json.loads(row.payload)["occurrences"] == 3 for row in deliveries)
        assert all(json.loads(row.payload)["is_new"] for row in deliveries)
        assert db.scalar(select(Finding.occurrences)) == 3
    scan(client, auth_headers, [item])
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(NotificationDelivery).where(NotificationDelivery.channel == "jira")) == 1
        assert db.scalar(select(func.count()).select_from(NotificationDelivery).where(NotificationDelivery.channel == "slack")) == 2


def test_import_history_distinguishes_clean_failed_and_complete(client, auth_headers):
    assert scan(client, auth_headers, {"findings": []}).status_code == 200
    broken = client.post("/import/scan", headers=auth_headers,
                         json={"parser": "generic-json", "content": '{"title":"SENSITIVE-INPUT",'})
    assert broken.status_code == 400
    valid = scan(client, auth_headers, [{"title": "Normal", "severity": "medium"}])
    history = client.get("/imports", headers=auth_headers).json()
    assert history["count"] == 3
    assert sorted(row["status"] for row in history["results"]) == ["completed", "completed", "failed"]
    assert "SENSITIVE-INPUT" not in json.dumps(history)
    with SessionLocal() as db:
        assert db.scalar(select(Signal.import_id)) == valid.json()["import_id"]


def test_import_database_failure_rolls_back_findings_and_notifications(client, auth_headers, monkeypatch):
    from app import main
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://slack.invalid/webhook")
    actual, calls = main._upsert_finding, 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("SENSITIVE-INTERNAL-DETAIL")
        return actual(*args, **kwargs)

    monkeypatch.setattr(main, "_upsert_finding", fail_second)
    response = scan(client, auth_headers, [{"title": "One", "severity": "high"}, {"title": "Two", "severity": "high"}])
    assert response.status_code == 500
    assert "SENSITIVE-INTERNAL-DETAIL" not in response.text
    with SessionLocal() as db:
        for model in (Finding, Signal, Asset, NotificationDelivery):
            assert db.scalar(select(func.count()).select_from(model)) == 0
        assert db.scalar(select(ImportRun.status)) == "failed"


def test_asset_context_updates_risk_and_later_signals_use_inventory(client, auth_headers):
    base = {"tool": "nuclei", "title": "Context", "severity": "high", "asset": "host", "project": "one"}
    created = client.post("/ingest/signal", headers=auth_headers, json=base).json()
    client.post("/assets/upsert", headers=auth_headers,
                json={"key": "host", "project": "one", "exposure": "internet", "criticality": "high"})
    finding = client.get(f"/findings/{created['finding_id']}", headers=auth_headers).json()
    assert (finding["risk_score"], finding["exposure"], finding["criticality"]) == (195, "internet", "high")
    later = client.post("/ingest/signal", headers=auth_headers, json={**base, "title": "Later"}).json()
    assert later["risk_score"] == 195
    client.post("/assets/upsert", headers=auth_headers,
                json={"key": "host", "project": "one", "exposure": "internal", "criticality": "low"})
    rows = client.get("/findings", headers=auth_headers).json()["results"]
    assert all(row["risk_score"] == 80 for row in rows)


def test_filtering_pagination_and_deterministic_order(client, auth_headers):
    report = [{"title": f"Issue {index}", "severity": "critical" if index == 0 else "low",
               "asset": f"host-{index}", "id": f"rule-{index}"} for index in range(105)]
    response = scan(client, auth_headers, report, project="pagination")
    assert response.status_code == 200, response.text
    first = client.get("/findings?limit=100&sort=risk_desc", headers=auth_headers).json()
    second = client.get("/findings?offset=100&sort=risk_desc", headers=auth_headers).json()
    assert first["count"] == second["count"] == 105
    assert len(first["results"]) == 100 and len(second["results"]) == 5
    assert len({row["id"] for row in first["results"] + second["results"]}) == 105
    assert first["results"][0]["severity"] == "critical"
    assert client.get("/findings?severity=critical&project=pagination&q=Issue", headers=auth_headers).json()["count"] == 1
    assert client.get("/assets?offset=100&project=pagination", headers=auth_headers).json()["page_count"] == 5
    assert client.get("/findings?q=%25", headers=auth_headers).json()["count"] == 0


def test_status_audit_uses_authenticated_actor(client, auth_headers):
    assert scan(client, auth_headers, [{"title": "Audit", "severity": "low"}]).status_code == 200
    row = client.get("/findings", headers=auth_headers).json()["results"][0]
    client.patch(f"/findings/{row['id']}", headers={**auth_headers, "X-SecOps-User": "alice"}, json={"status": "resolved"})
    assert client.get(f"/findings/{row['id']}", headers=auth_headers).json()["comments"][0]["author"] == "api-admin"


def test_operations_require_administrative_access(client, ingest_headers):
    for path in ("/imports", "/notifications"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers=ingest_headers).status_code == 401


def test_signal_body_limit_applies_before_validation(client, auth_headers, monkeypatch):
    monkeypatch.setenv("MAX_REQUEST_BYTES", "64")
    assert client.post("/ingest/signal", headers=auth_headers, json={"title": "x" * 200}).status_code == 413


def test_secret_source_fallback_is_redacted_before_storage(client, auth_headers, monkeypatch):
    from app import main
    from app.parsers.base import ParsedFinding, Severity
    sentinel = "SYNTHETIC-SECRET-MUST-NOT-ESCAPE"
    monkeypatch.setattr(main, "parse_scan_results", lambda **kwargs: [ParsedFinding(
        title="Credential", severity=Severity.HIGH, tool="credscan", asset="config.py",
        raw_data={"id": sentinel, "secret": sentinel},
    )])
    response = scan(client, auth_headers, {}, parser="credscan")
    assert response.status_code == 200, response.text
    assert sentinel not in client.get("/findings", headers=auth_headers).text
    with SessionLocal() as db:
        assert sentinel not in "".join(db.scalars(select(Signal.payload)))


def test_legacy_unscoped_bandit_identity_stays_stable(client, auth_headers):
    from app.main import make_fingerprint
    report = {"results": [{"test_id": "B101", "test_name": "assert_used", "issue_severity": "HIGH",
                            "filename": "app.py", "line_number": 10}]}
    assert scan(client, auth_headers, report, "bandit").status_code == 200
    row = client.get("/findings", headers=auth_headers).json()["results"][0]
    legacy_fingerprint = make_fingerprint("bandit", "B101: assert_used", "app.py", file_path="app.py", line_number=10)
    assert row["fingerprint"] == legacy_fingerprint
    assert row["source_id"] == "B101"


def test_direct_payloads_reject_database_incompatible_text(client, auth_headers):
    response = client.post("/assets/upsert", headers=auth_headers, json={"key": "x", "project": "\U0001f600" * 200})
    assert response.status_code == 422
    response = client.post("/ingest/signal", headers=auth_headers,
                           json={"tool": "test", "severity": "high", "title": "NUL\x00text"})
    assert response.status_code == 422


def test_invalid_unicode_scan_is_rejected_before_encoding(client, auth_headers):
    response = client.post("/import/scan", headers={**auth_headers, "Content-Type": "application/json"},
                           content=json.dumps({"parser": "generic-json", "content": "\ud800"}))
    assert response.status_code == 422


def test_source_fallback_is_revalidated_after_extraction(client, auth_headers, monkeypatch):
    from app import main
    from app.parsers.base import ParsedFinding, Severity
    monkeypatch.setattr(main, "parse_scan_results", lambda **kwargs: [ParsedFinding(
        title="Oversize source", severity=Severity.LOW, tool="generic-json", raw_data={"id": "x" * 2001},
    )])
    response = scan(client, auth_headers, [])
    assert response.status_code == 400
    assert client.get("/findings", headers=auth_headers).json()["count"] == 0


def test_interrupted_import_is_visible_and_reconciled(client, auth_headers):
    from datetime import timedelta
    from app.notifications.outbox import utcnow
    from app.notifications.worker import claim_delivery
    with SessionLocal.begin() as db:
        run = ImportRun(parser="generic-json", project="stale", actor="test", content_sha256="0" * 64,
                        created_at=utcnow() - timedelta(hours=1))
        db.add(run)
    history = client.get("/imports?project=stale", headers=auth_headers).json()
    assert history["results"][0]["status"] == "interrupted"
    assert "submit" in history["results"][0]["error"]
    assert claim_delivery() is None
    with SessionLocal() as db:
        assert db.scalar(select(ImportRun.status)) == "interrupted"


def test_timed_out_import_never_commits_partial_findings(client, auth_headers, monkeypatch):
    from datetime import timedelta
    from app import main
    actual = main._upsert_finding
    current_time = main.utcnow()
    clock = [current_time]
    monkeypatch.setattr(main, "utcnow", lambda: clock[0])
    def exceed_deadline(*args, **kwargs):
        result = actual(*args, **kwargs)
        clock[0] = current_time + timedelta(hours=1)
        return result
    monkeypatch.setattr(main, "_upsert_finding", exceed_deadline)
    response = scan(client, auth_headers, [{"title": "Timeout", "severity": "high"}])
    assert response.status_code == 408
    assert client.get("/findings", headers=auth_headers).json()["count"] == 0
    assert client.get("/imports", headers=auth_headers).json()["results"][0]["status"] == "failed"
