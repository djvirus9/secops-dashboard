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
    def http_server(self, label, response=None):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                received.append({"path": self.path, "authorization": self.headers.get("Authorization"),
                                 "api_key": self.headers.get("X-API-Key"), "body": body})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                value = response(self.path, body) if response else {"server": label}
                self.wfile.write(json.dumps(value).encode())

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
                   "GITHUB_SYNC_TOKEN": "ambient-token-that-must-never-be-used",
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
            self.assertEqual(environment["SESSION_COOKIE_SECURE"], "false")
            self.assertEqual(environment["GITHUB_SYNC_TOKEN"], "")
            self.assertEqual(environment["DASHBOARD_ORIGINS"], "http://127.0.0.1:5050,http://localhost:5050")

    def test_frontend_process_receives_no_backend_or_bootstrap_secrets(self):
        env = {"PATH": "/synthetic/bin", "BACKEND_URL": "http://127.0.0.1:8000",
               "DASHBOARD_ORIGINS": "http://127.0.0.1:5050", "API_KEY": "synthetic-admin",
               "INGEST_API_KEY": "synthetic-ingest", "DASHBOARD_PASSWORD": "synthetic-bootstrap",
               "DASHBOARD_USERNAME": "admin", "DATABASE_URL": "sqlite:///private.db",
               "PGPASSWORD": "synthetic-postgres", "JIRA_API_TOKEN": "synthetic-jira"}
        env["GITHUB_SYNC_TOKEN"] = "synthetic-github"
        child = local.frontend_environment(env)
        self.assertEqual(child, {name: env[name] for name in ("PATH", "BACKEND_URL", "DASHBOARD_ORIGINS")})

    def test_github_token_requires_hidden_terminal_input_and_stays_private(self):
        token = "github-synthetic-token-" + "x" * 32
        with tempfile.TemporaryDirectory() as directory, patch.object(local, "LOCAL", Path(directory)), \
                patch.object(local.sys.stdin, "isatty", return_value=False), patch.object(local.getpass, "getpass") as prompt:
            with self.assertRaisesRegex(RuntimeError, "interactive terminal"):
                local.github_token()
            prompt.assert_not_called()
            self.assertEqual(list(Path(directory).iterdir()), [])
        with tempfile.TemporaryDirectory() as directory, patch.object(local, "LOCAL", Path(directory)), \
                patch.object(local.sys.stdin, "isatty", return_value=True), \
                redirect_stdout(StringIO()) as output, \
                patch.object(local.sys.stdout, "isatty", return_value=True), \
                patch.object(local.getpass, "getpass", return_value=token):
            local.github_token()
            path = Path(directory) / "github-token"
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(local.read_github_token(), token)
            self.assertNotIn(token, output.getvalue())
            local.github_token(clear=True)
            self.assertFalse(path.exists())
            self.assertEqual(local.read_github_token(), "")

    def test_github_token_rejects_unsafe_files_and_invalid_input_without_printing_it(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(local, "LOCAL", Path(directory)):
            path = Path(directory) / "github-token"
            path.write_text("github-synthetic-token-" + "x" * 32)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "mode 0600"):
                local.read_github_token()
            path.unlink()
            target = Path(directory) / "other"
            target.write_text("github-synthetic-token-" + "x" * 32)
            target.chmod(0o600)
            path.symlink_to(target)
            with self.assertRaises(OSError):
                local.read_github_token()
        for token in ("too-short", "a" * 513, "a" * 40 + "\n", "a" * 40 + "\x00", "a" * 40 + "é"):
            with self.subTest(length=len(token)), self.assertRaises(RuntimeError) as error:
                local.validate_github_token(token)
            self.assertNotIn(token, str(error.exception))

    def test_only_backend_and_github_worker_receive_explicit_local_github_token(self):
        token = "github-synthetic-token-" + "x" * 32
        with tempfile.TemporaryDirectory() as directory, patch.object(local, "LOCAL", Path(directory)), \
                patch.dict(os.environ, {"GITHUB_SYNC_TOKEN": "ambient-ignored"}, clear=True):
            path = Path(directory) / "github-token"
            path.write_text(token)
            path.chmod(0o600)
            env = local.environment(5050, 8000)
            for name in ("backend", "github-worker"):
                self.assertEqual(local.service_environment(name, env)["GITHUB_SYNC_TOKEN"], token)
            for name in ("frontend", "worker", "migration"):
                self.assertNotIn("GITHUB_SYNC_TOKEN", local.service_environment(name, env))

    def test_github_token_refuses_getpass_echo_fallback(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(local, "LOCAL", Path(directory)), \
                patch.object(local.sys.stdin, "isatty", return_value=True), \
                patch.object(local.sys.stdout, "isatty", return_value=True), \
                patch.object(local.getpass, "getpass", side_effect=local.getpass.GetPassWarning):
            with self.assertRaisesRegex(RuntimeError, "cannot disable echo"):
                local.github_token()
            self.assertFalse((Path(directory) / "github-token").exists())

    def test_seed_uses_private_backend_key_without_bootstrap_login(self):
        backend, requests = self.http_server("backend", lambda path, body: {"imported": 8} if body else {"count": 0})
        frontend, browser_requests = self.http_server("frontend")
        state = {"api_port": int(backend.rsplit(":", 1)[1]), "port": int(frontend.rsplit(":", 1)[1])}
        auth = {"API_KEY": "synthetic-private-admin-key", "DASHBOARD_USERNAME": "admin",
                "DASHBOARD_PASSWORD": "old-password-replaced-in-dashboard"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "examples").mkdir()
            (root / "examples/demo-scan.json").write_text('{"findings": []}')
            with patch.object(local, "ROOT", root), patch.object(local, "running_state", return_value=state), \
                    patch.object(local, "healthy", return_value=True), patch.object(local, "credentials", return_value=auth), \
                    redirect_stdout(StringIO()) as output:
                local.seed()
            self.assertNotIn(auth["API_KEY"], output.getvalue())
            self.assertNotIn(auth["DASHBOARD_PASSWORD"], output.getvalue())
        self.assertEqual(browser_requests, [])
        self.assertEqual([request["path"] for request in requests], ["/findings?project=demo", "/import/scan"])
        self.assertTrue(all(request["api_key"] == auth["API_KEY"] and request["authorization"] is None for request in requests))
        self.assertNotIn(auth["DASHBOARD_PASSWORD"], str(requests))

    def test_password_recovery_requires_terminal_and_targets_only_local_database(self):
        with patch.object(local.sys.stdin, "isatty", return_value=False), patch.object(local.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "interactive terminal"):
                local.reset_password("admin")
            run.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / ".local"
            state.mkdir()
            (state / "secops.db").touch()
            (state / "env.json").write_text(json.dumps({"DASHBOARD_USERNAME": "admin", "DASHBOARD_PASSWORD": "initial",
                                                       "API_KEY": "private-admin", "INGEST_API_KEY": "private-ingest"}))
            python = root / "python"
            python.touch()
            with patch.object(local, "ROOT", root), patch.object(local, "LOCAL", state), patch.object(local, "PYTHON", python), \
                    patch.object(local, "running_state", return_value={}), patch.object(local.sys.stdin, "isatty", return_value=True), \
                    patch.object(local.sys.stdout, "isatty", return_value=True), patch.object(local.subprocess, "run") as run:
                local.reset_password("admin")
            self.assertEqual(run.call_args.args[0], [str(python), "-m", "app.accounts", "reset-password", "--username", "admin"])
            self.assertEqual(run.call_args.kwargs["env"]["DATABASE_URL"], f"sqlite:///{state / 'secops.db'}")

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
                    local.prepare({**credentials, "DATABASE_URL": "sqlite:///synthetic.db", "PGPASSWORD": "synthetic", "GITHUB_SYNC_TOKEN": "private-github"})
                installs = [call for call in calls.call_args_list if call.args[0][1:4] == ["-m", "pip", "install"]]
                self.assertEqual(len(installs), 1)
                for key in (*credentials, "DATABASE_URL", "PGPASSWORD", "GITHUB_SYNC_TOKEN"):
                    self.assertNotIn(key, installs[0].kwargs["env"])


if __name__ == "__main__":
    unittest.main()
