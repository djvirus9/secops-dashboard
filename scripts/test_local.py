"""Local helper regressions: python3 -m unittest discover -s scripts -p test_local.py.

Tests use temporary files, mocked process control, and ephemeral loopback HTTP
servers. They never read the app's .local credentials or start/stop its services.
"""
from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
from io import StringIO
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, HTTPServer


SPEC = importlib.util.spec_from_file_location("secops_local_under_test", Path(__file__).with_name("local.py"))
local = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(local)


class LocalHelperTests(unittest.TestCase):
    def http_server(self, label):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                received.append({"path": self.path, "authorization": self.headers.get("Authorization"), "body": body})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"server": label}).encode())

            do_POST = do_GET

            def log_message(self, *_):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.addCleanup(cleanup)
        return f"http://127.0.0.1:{server.server_port}", received

    def test_loopback_credentials_bypass_ambient_http_proxies(self):
        destination, direct_requests = self.http_server("destination")
        proxy, proxy_requests = self.http_server("proxy")
        environment = {"http_proxy": proxy, "HTTP_PROXY": proxy, "NO_PROXY": "", "no_proxy": ""}
        authorization = "Basic synthetic-test-value"
        with patch.dict(os.environ, environment, clear=True):
            for body in (None, {"content": "synthetic"}):
                with self.subTest(method="GET" if body is None else "POST"):
                    result = local.request_json(destination + "/api/test", headers={"Authorization": authorization}, body=body)
                    self.assertEqual(result, {"server": "destination"})
        self.assertEqual(proxy_requests, [])
        self.assertEqual(len(direct_requests), 2)
        self.assertTrue(all(request["authorization"] == authorization for request in direct_requests))
        self.assertEqual(json.loads(direct_requests[1]["body"]), {"content": "synthetic"})

    def test_stop_never_signals_a_reused_pid(self):
        state = {"pid": 31337, "run_id": "expected-run", "port": 5050, "api_port": 8000}
        for command in ("/usr/bin/other-application", f"python {local.SCRIPT} _serve different-run 5050 8000"):
            with self.subTest(command=command), patch.object(local, "read_json", return_value=state), \
                    patch.object(local.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, command)), \
                    patch.object(local.os, "kill") as send_signal, redirect_stdout(StringIO()):
                local.stop()
                send_signal.assert_not_called()

    def test_process_identity_requires_matching_command_and_run_token(self):
        state = {"pid": 31337, "run_id": "expected-run", "port": 5050, "api_port": 8000}
        command = f"python {local.SCRIPT} _serve expected-run 5050 8000\n"
        with patch.object(local, "read_json", return_value=state), \
                patch.object(local.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, command)):
            self.assertEqual(local.running_state(), state)
        with patch.object(local, "read_json", return_value=state), \
                patch.object(local.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, command)):
            self.assertEqual(local.running_state(), {})

    def test_stop_signals_only_the_confirmed_supervisor(self):
        state = {"pid": 31337, "run_id": "expected-run", "port": 5050, "api_port": 8000}
        with patch.object(local, "running_state", side_effect=[state, {}]), \
                patch.object(local.os, "kill") as send_signal, redirect_stdout(StringIO()):
            local.stop()
        send_signal.assert_called_once_with(state["pid"], local.signal.SIGTERM)

    def test_local_environment_disables_integrations_and_preserves_proxy_exclusions(self):
        credentials = {key: "synthetic" for key in ("API_KEY", "INGEST_API_KEY", "DASHBOARD_USERNAME", "DASHBOARD_PASSWORD")}
        ambient = {"DATABASE_URL": "postgresql://synthetic.invalid/db", "SLACK_WEBHOOK_URL": "https://synthetic.invalid/webhook",
                   "JIRA_BASE_URL": "https://synthetic.invalid", "JIRA_EMAIL": "test@example.invalid",
                   "JIRA_API_TOKEN": "synthetic", "JIRA_PROJECT_KEY": "DEMO",
                   "NO_PROXY": "upper.example.invalid", "no_proxy": "lower.example.invalid"}
        with tempfile.TemporaryDirectory() as directory, patch.object(local, "LOCAL", Path(directory)), \
                patch.object(local, "credentials", return_value=credentials), patch.dict(os.environ, ambient, clear=True):
            environment = local.environment(5050, 8000)
            self.assertEqual(environment["DATABASE_URL"], f"sqlite:///{Path(directory) / 'secops.db'}")
            for key in ("SLACK_WEBHOOK_URL", "JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"):
                self.assertEqual(environment[key], "")
            for key, original in (("NO_PROXY", "upper.example.invalid"), ("no_proxy", "lower.example.invalid")):
                self.assertTrue({original, "127.0.0.1", "localhost", "::1"}.issubset(environment[key].split(",")))
            self.assertEqual(os.environ["SLACK_WEBHOOK_URL"], ambient["SLACK_WEBHOOK_URL"])

    def test_credentials_are_private_and_persist_between_invocations(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(local, "LOCAL", Path(directory)):
            first = local.credentials()
            self.assertEqual(local.credentials(), first)
            self.assertEqual(stat.S_IMODE((Path(directory) / "env.json").stat().st_mode), 0o600)
            self.assertNotEqual(first["API_KEY"], first["INGEST_API_KEY"])

    def test_recreated_or_incomplete_venv_reinstalls_cached_requirements(self):
        for created in (True, False):
            with self.subTest(created_venv=created), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                python = root / ".venv/bin/python"
                if not created:
                    python.parent.mkdir(parents=True)
                    python.touch()
                for relative in ("frontend/node_modules/next/package.json", "frontend/.next/standalone/server.js"):
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.touch()
                runtime = [[3, 12, 0], "/synthetic-python"]
                cached = {"requirements": "requirements", "packages": "packages", "frontend": "frontend",
                          "python": runtime, "node": "v24.0.0"}
                credentials = {key: "synthetic" for key in ("API_KEY", "INGEST_API_KEY", "DASHBOARD_USERNAME", "DASHBOARD_PASSWORD")}

                def run(command, **kwargs):
                    # A recreated venv forces setup even if an import probe is
                    # unexpectedly successful; an existing incomplete one does too.
                    failed_probe = not created and "import fastapi" in str(command)
                    return subprocess.CompletedProcess(command, int(failed_probe))

                with patch.object(local, "ROOT", root), patch.object(local, "PYTHON", python), \
                        patch.object(local, "LOCAL", root / ".local"), patch.object(local, "read_json", return_value=cached), \
                        patch.object(local, "credentials", return_value=credentials), patch.object(local, "save_json"), \
                        patch.object(local, "fingerprint", side_effect=["requirements", "packages", "frontend"]), \
                        patch.object(local.shutil, "which", return_value="/synthetic-node"), patch.object(local.shutil, "copytree"), \
                        patch.object(local.subprocess, "check_output", side_effect=["v24.0.0", json.dumps(runtime)]), \
                        patch.object(local.subprocess, "run", side_effect=run) as calls, redirect_stdout(StringIO()):
                    local.prepare({**credentials, "DATABASE_URL": "sqlite:///synthetic.db", "PGPASSWORD": "synthetic"})
                installs = [call for call in calls.call_args_list if call.args[0][1:4] == ["-m", "pip", "install"]]
                self.assertEqual(len(installs), 1)
                for key in (*credentials, "DATABASE_URL", "PGPASSWORD"):
                    self.assertNotIn(key, installs[0].kwargs["env"])


if __name__ == "__main__":
    unittest.main()
