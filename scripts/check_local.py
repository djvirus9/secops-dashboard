"""Exercise the local launcher on a fresh disposable CI checkout."""
from __future__ import annotations

from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import stat
import secrets
import subprocess
import sys
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"


def run(command: str, *, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "scripts/local.py", command], cwd=ROOT,
                          check=True, capture_output=capture, text=True)


def main() -> None:
    if os.environ.get("SECOPS_LOCAL_SMOKE_TEST") != "1" or LOCAL.exists():
        raise SystemExit("Use SECOPS_LOCAL_SMOKE_TEST=1 on a fresh disposable checkout without .local")
    # The launcher must not pick up integration settings from the invoking shell.
    os.environ.update(SLACK_WEBHOOK_URL="http://127.0.0.1:9/unintended-slack",
                      JIRA_BASE_URL="http://127.0.0.1:9/unintended-jira",
                      JIRA_EMAIL="ci@example.invalid", JIRA_API_TOKEN="synthetic-unused-token",
                      JIRA_PROJECT_KEY="UNUSED", GITHUB_SYNC_TOKEN="ambient-synthetic-token-must-not-be-used")
    try:
        run("start")
        run("status")
        auth_bytes = (LOCAL / "env.json").read_bytes()
        auth = json.loads(auth_bytes)
        assert stat.S_IMODE((LOCAL / "env.json").stat().st_mode) == 0o600
        base = "http://127.0.0.1:5050"
        cookies = CookieJar()
        opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(cookies))
        anonymous = build_opener(ProxyHandler({}))

        def request(path, *, body=None, authenticated=True, origin=base):
            headers = {}
            if body is not None:
                headers.update({"Content-Type": "application/json", "Origin": origin})
            req = Request(base + path, headers=headers, data=json.dumps(body).encode() if body is not None else None)
            try:
                with (opener if authenticated else anonymous).open(req, timeout=10) as response:
                    return response.status, json.load(response)
            except HTTPError as exc:
                return exc.code, None

        assert request("/api/findings", authenticated=False)[0] == 401
        assert request("/api/auth/login", body={"username": auth['DASHBOARD_USERNAME'],
                                                "password": auth['DASHBOARD_PASSWORD']})[0] == 200
        session = next(cookie for cookie in cookies if cookie.name == "secops_session")
        assert session.has_nonstandard_attr("HttpOnly")
        assert session.get_nonstandard_attr("SameSite").lower() == "strict"
        assert not session.secure, "The disposable loopback HTTP demo needs non-Secure cookies"
        assert request("/api/auth/me")[1]["user"]["role"] == "admin"
        status, sync = request("/api/github-sync")
        assert status == 200 and sync["configured"] is False and sync["count"] == 0
        assert not (LOCAL / "github-token").exists()
        subprocess.run([str(ROOT / ".venv/bin/python"), "-m", "app.github_sync.worker", "--health"],
                       cwd=ROOT / "backend", check=True, capture_output=True,
                       env={**os.environ, "DATABASE_URL": f"sqlite:///{LOCAL / 'secops.db'}", "GITHUB_SYNC_TOKEN": ""})
        for name in ("API_KEY", "INGEST_API_KEY", "DASHBOARD_PASSWORD"):
            output = run("credentials", capture=True).stdout
            assert auth[name] not in output, "Credentials must not be printed into captured logs"
        original_state = json.loads((LOCAL / "run.json").read_text())
        run("start")
        assert json.loads((LOCAL / "run.json").read_text())["run_id"] == original_state["run_id"]
        run("seed")
        status, findings = request("/api/findings?project=demo")
        assert status == 200 and findings["count"] == 8
        assert all(row["occurrences"] == 1 for row in findings["results"])
        rejected = {"tool": "demo", "severity": "low", "title": "Rejected request", "project": "demo"}
        assert request("/api/ingest/signal", body=rejected, origin="https://untrusted.invalid")[0] == 403
        run("seed")
        assert request("/api/findings?project=demo")[1] == findings
        assert request("/api/notifications")[1]["count"] == 0, "Local demo integrations must remain disabled"
        finding_id = findings["results"][0]["id"]
        message = "Local launcher persistence check"
        assert request(f"/api/findings/{finding_id}/comments", body={"content": message})[0] == 200
        assert request("/api/auth/logout", body={}, origin="https://untrusted.invalid")[0] == 403
        new_password = secrets.token_urlsafe(48)
        assert request("/api/auth/password", body={"current_password": auth['DASHBOARD_PASSWORD'],
                                                   "new_password": new_password})[0] == 200
        assert request("/api/auth/me")[0] == 401, "Password changes must revoke the current session"
        assert request("/api/auth/login", body={"username": auth['DASHBOARD_USERNAME'], "password": new_password})[0] == 200
        run("seed")  # Seeding uses the private API key even after the user changes password.
        run("stop")
        stopped = subprocess.run([sys.executable, "scripts/local.py", "status"], cwd=ROOT,
                                 capture_output=True, text=True)
        assert stopped.returncode == 1
        run("start")
        run("status")
        assert (LOCAL / "env.json").read_bytes() == auth_bytes, "Restart must preserve credentials"
        assert request("/api/auth/me")[0] == 200, "Live sessions must survive a service restart"
        assert request("/api/findings?project=demo")[1]["count"] == 8
        detail = request(f"/api/findings/{finding_id}")[1]
        assert any(c["content"] == message and c["author"] == "admin" for c in detail["comments"])
        assert request("/api/notifications")[1]["count"] == 0
        assert request("/api/auth/logout", body={})[0] == 200
        assert request("/api/auth/me")[0] == 401
        assert request("/api/auth/login", body={"username": auth['DASHBOARD_USERNAME'],
                                                "password": auth['DASHBOARD_PASSWORD']})[0] == 401, "Bootstrap must not reset an existing password"
        assert request("/api/auth/login", body={"username": auth['DASHBOARD_USERNAME'], "password": new_password})[0] == 200
        print("Local quickstart passed: sessions, logout, origin protection, password-change/restart persistence, private seeding, isolated integrations")
    finally:
        # The guard above guarantees this state belongs to this disposable test.
        subprocess.run([sys.executable, "scripts/local.py", "stop"], cwd=ROOT, check=False)


if __name__ == "__main__":
    main()
