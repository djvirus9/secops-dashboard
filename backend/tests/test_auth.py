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
