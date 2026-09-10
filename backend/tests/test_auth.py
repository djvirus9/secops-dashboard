from __future__ import annotations


def test_health_and_readiness_are_public(client):
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200


def test_protected_routes_require_api_key(client, auth_headers):
    assert client.get("/findings").status_code == 401
    assert client.get("/docs").status_code == 401
    assert client.get("/findings", headers=auth_headers).status_code == 200


def test_host_header_cannot_bypass_authentication(client):
    response = client.post(
        "/assets/upsert",
        json={"key": "must-not-be-created"},
        headers={"Host": "example.com/health?x="},
    )
    assert response.status_code in {400, 401}
    assert response.status_code != 200


def test_missing_api_key_fails_closed(client, monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("ALLOW_INSECURE_NO_AUTH", raising=False)
    response = client.get("/findings")
    assert response.status_code == 503


def test_insecure_no_auth_requires_explicit_opt_in(client, monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.setenv("ALLOW_INSECURE_NO_AUTH", "true")
    assert client.get("/findings").status_code == 200


def test_ingest_key_is_limited_to_ingestion_routes(client, ingest_headers):
    payload = {
        "tool": "nuclei",
        "severity": "medium",
        "title": "Scoped ingestion test",
        "asset": "scanner.example.test",
    }

    assert client.post(
        "/ingest/signal", headers=ingest_headers, json=payload
    ).status_code == 200
    assert client.get("/findings", headers=ingest_headers).status_code == 401
    assert client.post(
        "/assets/upsert",
        headers=ingest_headers,
        json={"key": "must-not-be-created.example.test"},
    ).status_code == 401


def test_cors_preflight_does_not_require_api_credentials(client):
    response = client.options(
        "/findings",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-api-key",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_unauthenticated_import_is_rejected_before_body_processing(client, monkeypatch):
    monkeypatch.setenv("MAX_IMPORT_REQUEST_BYTES", "1")

    response = client.post("/import/scan", json={"content": "oversized"})

    assert response.status_code == 401


def test_admin_and_ingest_keys_must_be_distinct(client, auth_headers, monkeypatch):
    monkeypatch.setenv("INGEST_API_KEY", auth_headers["X-API-Key"])

    response = client.get("/findings", headers=auth_headers)

    assert response.status_code == 503
