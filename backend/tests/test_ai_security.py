from __future__ import annotations


def test_ai_security_catalog_is_synthetic_and_authenticated(client, auth_headers):
    assert client.get("/ai-security/scenarios").status_code == 401

    response = client.get("/ai-security/scenarios", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["simulation"] is True
    assert body["count"] == 10
    assert sum(item["kind"] == "attack" for item in body["scenarios"]) == 8
    assert sum(item["kind"] == "benign" for item in body["scenarios"]) == 2
    assert all("plan" not in item for item in body["scenarios"])


def test_prompt_only_mode_demonstrates_the_unsafe_baseline(client, auth_headers):
    response = client.post(
        "/ai-security/run",
        headers=auth_headers,
        json={"scenario_id": "indirect-finding-injection", "mode": "prompt_only"},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["simulation"] is True
    assert result["disposition"] == "executed"
    assert result["attack_succeeded"] is True
    assert result["controls"][0]["result"] == "missed"


def test_policy_mode_contains_every_attack_and_preserves_benign_reads(
    client, auth_headers
):
    catalog = client.get("/ai-security/scenarios", headers=auth_headers).json()

    results = {}
    for scenario in catalog["scenarios"]:
        response = client.post(
            "/ai-security/run",
            headers=auth_headers,
            json={"scenario_id": scenario["id"], "mode": "policy_enforced"},
        )
        assert response.status_code == 200
        results[scenario["id"]] = response.json()

    attack_results = [
        result for result in results.values() if result["kind"] == "attack"
    ]
    benign_results = [
        result for result in results.values() if result["kind"] == "benign"
    ]
    assert all(result["attack_succeeded"] is False for result in attack_results)
    assert all(result["disposition"] == "allowed" for result in benign_results)
    assert results["unapproved-status-change"]["disposition"] == "approval_required"
    assert results["unsafe-markdown-rendering"]["disposition"] == "sanitized"
    assert results["unbounded-tool-loop"]["disposition"] == "rate_limited"
    assert results["cross-tenant-retrieval"]["disposition"] == "blocked"
    assert "[REDACTED_SYNTHETIC_SECRET]" in results[
        "synthetic-secret-disclosure"
    ]["rendered_output"]


def test_evaluation_summary_reports_method_and_measured_counts(client, auth_headers):
    response = client.get("/ai-security/evaluation", headers=auth_headers)

    assert response.status_code == 200
    summary = response.json()
    assert summary["simulation"] is True
    assert summary["corpus_size"] == 10
    assert summary["attack_cases"] == 8
    assert summary["benign_cases"] == 2
    assert summary["prompt_only"] == {
        "attack_successes": 8,
        "attack_success_rate": 100.0,
    }
    assert summary["policy_enforced"] == {
        "attack_successes": 0,
        "attack_success_rate": 0.0,
        "benign_allowed": 2,
        "false_refusals": 0,
        "false_refusal_rate": 0.0,
    }
    assert "no model or external tool is called" in summary["method"]


def test_ai_security_run_rejects_unknown_modes_scenarios_and_extra_fields(
    client, auth_headers
):
    unknown = client.post(
        "/ai-security/run",
        headers=auth_headers,
        json={"scenario_id": "missing-scenario", "mode": "policy_enforced"},
    )
    invalid_mode = client.post(
        "/ai-security/run",
        headers=auth_headers,
        json={"scenario_id": "benign-summary", "mode": "unrestricted"},
    )
    extra_field = client.post(
        "/ai-security/run",
        headers=auth_headers,
        json={
            "scenario_id": "benign-summary",
            "mode": "policy_enforced",
            "execute_tools": True,
        },
    )

    assert unknown.status_code == 404
    assert invalid_mode.status_code == 422
    assert extra_field.status_code == 422


def test_ingest_key_cannot_access_the_ai_security_lab(client, ingest_headers):
    assert client.get(
        "/ai-security/scenarios", headers=ingest_headers
    ).status_code == 401
    assert client.post(
        "/ai-security/run",
        headers=ingest_headers,
        json={"scenario_id": "benign-summary", "mode": "policy_enforced"},
    ).status_code == 401
