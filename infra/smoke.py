"""Synthetic smoke check for the disposable Compose stack in CI."""
from __future__ import annotations

import base64
import json
import os
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def main() -> None:
    if os.environ.get("SECOPS_SMOKE_TEST") != "1":
        raise SystemExit("SECOPS_SMOKE_TEST=1 is required; run only against a disposable local stack")
    origin = "http://localhost:5000"
    token = base64.b64encode(
        f"{os.environ['DASHBOARD_USERNAME']}:{os.environ['DASHBOARD_PASSWORD']}".encode()
    ).decode()

    def request(path, *, body=None, authenticated=True, request_origin=origin):
        headers = {}
        if authenticated:
            headers["Authorization"] = f"Basic {token}"
        if body is not None:
            headers.update({"Content-Type": "application/json", "Origin": request_origin})
        req = Request(origin + path, headers=headers,
                      data=json.dumps(body).encode() if body is not None else None)
        try:
            with urlopen(req, timeout=20) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, None

    assert request("/api/findings", authenticated=False)[0] == 401
    status, initial = request("/api/findings?project=ci-smoke")
    assert status == 200 and initial["count"] == 0, "Smoke tests require a fresh disposable database"
    payload = {
        "tool": "semgrep", "title": "CI synthetic finding", "severity": "medium",
        "asset": "ci-smoke.internal", "project": "ci-smoke",
    }
    assert request("/api/ingest/signal", body=payload, request_origin="https://untrusted.invalid")[0] == 403
    assert request("/api/ingest/signal", body=payload)[0] == 200
    status, findings = request("/api/findings?project=ci-smoke")
    assert status == 200
    assert len(findings["results"]) == 1
    finding = findings["results"][0]
    assert finding["title"] == payload["title"]
    assert finding["occurrences"] == 1, "Rejected cross-origin request must not write data"
    assert request("/api/ingest/signal", body=payload)[0] == 200
    status, replay = request("/api/findings?project=ci-smoke")
    assert status == 200 and replay["count"] == 1
    assert replay["results"][0]["id"] == finding["id"]
    assert replay["results"][0]["occurrences"] == 2
    comment = "CI synthetic restore verification"
    assert request(f"/api/findings/{finding['id']}/comments", body={"content": comment})[0] == 200
    status, detail = request(f"/api/findings/{finding['id']}")
    assert status == 200 and len(detail["comments"]) == 1
    assert detail["comments"][0]["content"] == comment
    assert detail["comments"][0]["author"] == os.environ["DASHBOARD_USERNAME"]
    print("Compose authentication, origin enforcement, persisted ingestion/replay and comment audit passed")


if __name__ == "__main__":
    main()
