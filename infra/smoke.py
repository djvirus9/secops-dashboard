"""Synthetic smoke check for the disposable Compose stack in CI."""
from __future__ import annotations

from http.cookiejar import CookieJar
import json
import os
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener


def main() -> None:
    if os.environ.get("SECOPS_SMOKE_TEST") != "1":
        raise SystemExit("SECOPS_SMOKE_TEST=1 is required; run only against a disposable local stack")
    origin = "http://localhost:5000"
    cookies = CookieJar()
    browser = build_opener(ProxyHandler({}), HTTPCookieProcessor(cookies))
    anonymous = build_opener(ProxyHandler({}))

    def request(path, *, body=None, method=None, authenticated=True, request_origin=origin, api_key=None):
        headers = {}
        if api_key:
            headers["X-API-Key"] = api_key
        if body is not None:
            headers.update({"Content-Type": "application/json", "Origin": request_origin})
        req = Request(("http://127.0.0.1:8000" if api_key else origin) + path, headers=headers,
                      data=json.dumps(body).encode() if body is not None else None, method=method)
        try:
            opener = browser if authenticated and not api_key else anonymous
            with opener.open(req, timeout=20) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, None

    assert request("/api/findings", authenticated=False)[0] == 401
    assert request("/api/auth/login", body={"username": os.environ['DASHBOARD_USERNAME'],
                                             "password": os.environ['DASHBOARD_PASSWORD']})[0] == 200
    session = next(cookie for cookie in cookies if cookie.name == "secops_session")
    assert session.has_nonstandard_attr("HttpOnly")
    assert session.get_nonstandard_attr("SameSite").lower() == "strict"
    user = request("/api/auth/me")[1]["user"]
    assert user["role"] == "admin"
    status, jira = request("/api/jira-sync")
    assert status == 200 and jira["configured"] is False and jira["enabled"] is False and jira["count"] == 0
    status, automation = request("/api/automation")
    assert status == 200 and automation["slack_configured"] is False and not automation["policies"]
    status, sync = request("/api/github-sync")
    assert status == 200 and sync["configured"] is False and sync["count"] == 0
    status, intelligence = request("/api/intelligence/status")
    assert status == 200
    assert {source["source"] for source in intelligence["sources"]} == {"cisa_kev", "first_epss"}
    assert all(source["last_synced_at"] is None for source in intelligence["sources"])
    status, connection = request("/api/github-sync", body={
        "repository": "synthetic-ci/no-network-requests", "project": "ci-smoke",
        "sources": ["code_scanning"], "interval_minutes": 60,
    })
    assert status == 201
    assert request(f"/api/github-sync/{connection['connection']['id']}/sync", body={})[0] == 503
    assert request("/api/github-sync")[1]["count"] == 1
    status, initial = request("/api/findings?project=ci-smoke")
    assert status == 200 and initial["count"] == 0, "Smoke tests require a fresh disposable database"
    status, team = request("/api/catalog/teams", body={"name": "CI smoke owners", "contact": "ci@example.invalid"})
    assert status == 201
    team_id = team["team"]["id"]
    assert request("/api/catalog/projects", body={
        "name": "ci-smoke", "display_name": "CI smoke", "team_id": team_id,
    })[0] == 201
    assert request(f"/api/ownership/teams/{team_id}/members/{user['id']}", method="PUT", body={})[0] == 200
    status, members = request(f"/api/ownership/teams/{team_id}/members")
    assert status == 200 and [member["id"] for member in members["results"]] == [user["id"]]
    status, rule = request("/api/ownership/rules?project=ci-smoke", method="PUT", body={
        "enabled": True, "default_assignee": user["username"],
    })
    assert status == 200 and rule["enabled"] and rule["ready"]
    assert request("/api/coverage", body={
        "project": "ci-smoke", "source_type": "scanner", "source": "semgrep", "interval_hours": 24,
    })[0] == 201
    status, policy = request("/api/automation/policies?project=ci-smoke", method="PUT", body={
        "enabled": False, "warn_before_hours": 24, "reminder_hours": 24, "notify_slack": False,
    })
    assert status == 200 and policy["policy"]["enabled"] is False and policy["policy"]["notify_slack"] is False
    assert request("/api/automation/evaluate?project=ci-smoke", body={})[0] == 409
    assert request("/api/automation/alerts?state=all&project=ci-smoke")[1]["count"] == 0
    payload = {
        "tool": "semgrep", "title": "CI synthetic finding", "severity": "medium",
        "asset": "ci-smoke.internal", "project": "ci-smoke",
    }
    assert request("/api/ingest/signal", body=payload, request_origin="https://untrusted.invalid")[0] == 403
    ingest_key = os.environ["INGEST_API_KEY"]
    assert request("/findings", api_key=ingest_key)[0] == 401
    assert request("/ingest/signal", body=payload, api_key=ingest_key)[0] == 200
    status, findings = request("/api/findings?project=ci-smoke")
    assert status == 200
    assert len(findings["results"]) == 1
    finding = findings["results"][0]
    assert finding["title"] == payload["title"]
    assert finding["assignee"] == user["username"]
    assert finding["ownership"] == {"status": "assigned", "team_id": team_id, "team_name": "CI smoke owners"}
    status, queue = request(f"/api/ownership/queue?view=team&team_id={team_id}")
    assert status == 200 and queue["count"] == 1 and queue["results"][0]["id"] == finding["id"]
    assert request("/api/ownership/queue?view=unassigned&project=ci-smoke")[1]["count"] == 0
    assert finding["priority_score"] == 20
    assert finding["remediation_due_at"] is not None
    assert finding["sla_status"] in {"on_track", "due_soon"}
    assert finding["occurrences"] == 1, "Rejected cross-origin request must not write data"
    status, scanner = request("/api/scanner-tokens", body={
        "name": "CI disposable scanner", "project": "ci-smoke", "expires_in_days": 1,
    })
    assert status == 201
    scanner_key = scanner["token"]
    assert request("/findings", api_key=scanner_key)[0] == 401
    # Project authorization intentionally conceals inaccessible resources with 404.
    assert request("/ingest/signal", body={**payload, "project": "forbidden-project"}, api_key=scanner_key)[0] == 404
    status, forbidden = request("/api/findings?project=forbidden-project")
    assert status == 200 and forbidden["count"] == 0, "Rejected scanner scope must not create findings"
    assert request("/ingest/signal", body=payload, api_key=scanner_key)[0] == 200
    assert request(f"/api/scanner-tokens/{scanner['scanner_token']['id']}/revoke", body={})[0] == 200
    assert request("/ingest/signal", body=payload, api_key=scanner_key)[0] == 401
    status, replay = request("/api/findings?project=ci-smoke")
    assert status == 200 and replay["count"] == 1
    assert replay["results"][0]["id"] == finding["id"]
    assert replay["results"][0]["occurrences"] == 2
    comment = "CI synthetic restore verification"
    assert request(f"/api/findings/{finding['id']}/comments", body={"content": comment})[0] == 200
    status, detail = request(f"/api/findings/{finding['id']}")
    assert status == 200 and len(detail["comments"]) == 2
    assert sum(row["action_type"] == "ownership" for row in detail["comments"]) == 1, "Replay must not reroute ownership"
    assert detail["comments"][0]["content"] == comment
    assert detail["comments"][0]["author"] == os.environ["DASHBOARD_USERNAME"]
    status, saved_view = request("/api/saved-views", body={
        "name": "CI restore verification", "filters": {"project": "ci-smoke", "severity": "medium"},
    })
    assert status == 201
    status, views = request("/api/saved-views")
    assert status == 200 and len(views["results"]) == 1
    assert views["results"][0]["id"] == saved_view["id"]
    assert views["results"][0]["filters"]["project"] == "ci-smoke"
    assert request("/api/auth/logout", body={}, request_origin="https://untrusted.invalid")[0] == 403
    assert request("/api/auth/logout", body={})[0] == 200
    assert request("/api/auth/me")[0] == 401
    print("Compose cookie authentication/logout, origins, scoped scanner-token revocation, idle GitHub/Jira/intelligence configuration, team ownership routing, disabled in-app automation, priority/SLA ingestion, replay, comments and saved views passed")


if __name__ == "__main__":
    main()
