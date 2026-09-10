"""Exercise the local launcher on a fresh disposable CI checkout."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

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
                      JIRA_PROJECT_KEY="UNUSED")
    try:
        run("start")
        run("status")
        auth_bytes = (LOCAL / "env.json").read_bytes()
        auth = json.loads(auth_bytes)
        assert stat.S_IMODE((LOCAL / "env.json").stat().st_mode) == 0o600
        token = base64.b64encode(f"{auth['DASHBOARD_USERNAME']}:{auth['DASHBOARD_PASSWORD']}".encode()).decode()
        base = "http://127.0.0.1:5050"
        opener = build_opener(ProxyHandler({}))

        def request(path, *, body=None, authenticated=True, origin=base):
            headers = {"Authorization": f"Basic {token}"} if authenticated else {}
            if body is not None:
                headers.update({"Content-Type": "application/json", "Origin": origin})
            req = Request(base + path, headers=headers, data=json.dumps(body).encode() if body is not None else None)
            try:
                with opener.open(req, timeout=10) as response:
                    return response.status, json.load(response)
            except HTTPError as exc:
                return exc.code, None

        assert request("/api/findings", authenticated=False)[0] == 401
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
        run("stop")
        stopped = subprocess.run([sys.executable, "scripts/local.py", "status"], cwd=ROOT,
                                 capture_output=True, text=True)
        assert stopped.returncode == 1
        run("start")
        run("status")
        assert (LOCAL / "env.json").read_bytes() == auth_bytes, "Restart must preserve credentials"
        assert request("/api/findings?project=demo")[1]["count"] == 8
        detail = request(f"/api/findings/{finding_id}")[1]
        assert any(c["content"] == message and c["author"] == "admin" for c in detail["comments"])
        assert request("/api/notifications")[1]["count"] == 0
        print("Local quickstart passed: authentication, origin protection, demo data, isolated integrations, idempotency, restart persistence")
    finally:
        # The guard above guarantees this state belongs to this disposable test.
        subprocess.run([sys.executable, "scripts/local.py", "stop"], cwd=ROOT, check=False)


if __name__ == "__main__":
    main()
