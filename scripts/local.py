#!/usr/bin/env python3
"""Run a private local demo without Docker. Requires Python 3.12+ and Node 24+."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
SCRIPT = Path(__file__).resolve()
PYTHON = ROOT / ".venv/bin/python"


def save_json(path: Path, data: dict) -> None:
    temporary = path.with_suffix(".tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as output:
        json.dump(data, output, indent=2)
        output.write("\n")
    temporary.replace(path)
    path.chmod(0o600)


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return {}


def running_state() -> dict:
    state = read_json(LOCAL / "run.json")
    if not state:
        return {}
    result = subprocess.run(["ps", "-ww", "-p", str(state["pid"]), "-o", "command="],
                            capture_output=True, text=True)
    # A PID alone is insufficient: never signal an unrelated process after reuse.
    expected = f"{SCRIPT} _serve {state['run_id']} "
    return state if result.returncode == 0 and expected in result.stdout else {}


def credentials() -> dict:
    path = LOCAL / "env.json"
    if not path.exists():
        save_json(path, {
            "DASHBOARD_USERNAME": "admin",
            **{key: secrets.token_hex(32) for key in (
                "DASHBOARD_PASSWORD", "API_KEY", "INGEST_API_KEY")},
        })
    path.chmod(0o600)
    values = read_json(path)
    required = ("DASHBOARD_USERNAME", "DASHBOARD_PASSWORD", "API_KEY", "INGEST_API_KEY")
    if any(not isinstance(values.get(key), str) or not values[key] for key in required):
        raise RuntimeError("Local credentials are incomplete; restore .local/env.json before starting")
    return {key: values[key] for key in required}


def environment(port: int, api_port: int) -> dict[str, str]:
    origin = f"http://127.0.0.1:{port}"
    env = {**os.environ, **credentials(),
           "DATABASE_URL": f"sqlite:///{LOCAL / 'secops.db'}",
           "ALLOWED_HOSTS": "localhost,127.0.0.1", "BACKEND_URL": f"http://127.0.0.1:{api_port}",
           "DASHBOARD_ORIGINS": f"{origin},http://localhost:{port}",
           "CORS_ORIGINS": f"{origin},http://localhost:{port}",
           "HOSTNAME": "127.0.0.1", "PORT": str(port), "NODE_ENV": "production",
           "ALLOW_INSECURE_NO_AUTH": "false", "ALLOW_UNVERIFIED_PARSERS": "false",
           "STORE_RAW_SCAN_DATA": "false", "NEXT_TELEMETRY_DISABLED": "1",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
    # Local demos cannot accidentally send real messages using ambient credentials.
    for key in ("SLACK_WEBHOOK_URL", "JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"):
        env[key] = ""
    for key in ("NO_PROXY", "no_proxy"):
        env[key] = ",".join(filter(None, (env.get(key), "127.0.0.1", "localhost", "::1")))
    return env


def request_json(url: str, *, headers: dict | None = None, body: dict | None = None):
    headers = dict(headers or {})
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, headers=headers, data=json.dumps(body).encode() if body is not None else None)
    # Never send local dashboard credentials through a configured network proxy.
    with build_opener(ProxyHandler({})).open(request, timeout=5) as response:
        return json.load(response)


def healthy(state: dict) -> bool:
    if not state.get("ready"):
        return False
    try:
        request_json(f"http://127.0.0.1:{state['api_port']}/ready")
        request_json(f"http://127.0.0.1:{state['port']}/_health")
        return True
    except (OSError, URLError, ValueError):
        return False


def check_port(port: int) -> None:
    with socket.socket() as connection:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            connection.bind(("127.0.0.1", port))
        except OSError as exc:
            raise RuntimeError(f"Port {port} is already in use; choose --port or --api-port") from exc


def fingerprint(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        if path.is_file():
            digest.update(str(path.relative_to(ROOT)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def prepare(env: dict) -> None:
    if sys.version_info < (3, 12):
        raise RuntimeError("Use Python 3.12 or newer")
    for command in ("node", "npm"):
        if not shutil.which(command):
            raise RuntimeError(f"Install Node.js 24 LTS (including {command}) and run start again")
    version = subprocess.check_output(["node", "--version"], text=True).strip()
    if int(version.lstrip("v").split(".")[0]) < 24:
        raise RuntimeError("Node.js 24 or newer is required; Node 24 LTS is recommended")
    cached = read_json(LOCAL / "build.json")
    created_venv = not PYTHON.exists()
    if not PYTHON.exists():
        subprocess.run([sys.executable, "-m", "venv", str(ROOT / ".venv")], check=True)
    python_runtime = json.loads(subprocess.check_output([
        str(PYTHON), "-c", "import json,sys; print(json.dumps([sys.version_info[:3], sys.base_prefix]))"], text=True))
    if tuple(python_runtime[0]) < (3, 12):
        raise RuntimeError("The existing .venv uses Python older than 3.12; recreate it with a supported Python")
    dependencies_present = subprocess.run([
        str(PYTHON), "-c", "import fastapi,sqlalchemy,psycopg2,uvicorn,alembic,defusedxml,dotenv"],
        capture_output=True).returncode == 0
    build_env = dict(env)
    for key in (*credentials(), "DATABASE_URL", "PGPASSWORD"):
        build_env.pop(key, None)
    requirements = fingerprint([ROOT / "backend/requirements.txt"])
    if created_venv or not dependencies_present or cached.get("requirements") != requirements or cached.get("python") != python_runtime:
        print("Installing backend dependencies…", flush=True)
        if subprocess.run([str(PYTHON), "-c", "import pip"], capture_output=True).returncode:
            subprocess.run([str(PYTHON), "-m", "ensurepip", "--upgrade"], check=True)
        subprocess.run([str(PYTHON), "-m", "pip", "install", "-r", "requirements.txt"],
                       cwd=ROOT / "backend", env=build_env, check=True)
    frontend = ROOT / "frontend"
    packages = fingerprint([frontend / "package.json", frontend / "package-lock.json"])
    if cached.get("packages") != packages or cached.get("node") != version or not (frontend / "node_modules/next/package.json").exists():
        print("Installing frontend dependencies…", flush=True)
        subprocess.run(["npm", "ci", "--include=dev"], cwd=frontend, env=build_env, check=True)
    sources = [frontend / name for name in (
        "package.json", "package-lock.json", "next.config.js", "tsconfig.json", "proxy.ts",
        "postcss.config.js", "tailwind.config.js")]
    for directory in ("pages", "components", "lib", "styles", "public"):
        sources.extend((frontend / directory).rglob("*"))
    build = fingerprint(sources)
    server = frontend / ".next/standalone/server.js"
    if cached.get("frontend") != build or cached.get("node") != version or not server.exists():
        print("Building the dashboard…", flush=True)
        subprocess.run(["npm", "run", "build"], cwd=frontend, env=build_env, check=True)
    shutil.copytree(frontend / "public", frontend / ".next/standalone/public", dirs_exist_ok=True)
    shutil.copytree(frontend / ".next/static", frontend / ".next/standalone/.next/static", dirs_exist_ok=True)
    save_json(LOCAL / "build.json", {"requirements": requirements, "packages": packages, "frontend": build,
                                    "python": python_runtime, "node": version})
    subprocess.run([str(PYTHON), "-m", "app.deployment"], cwd=ROOT / "backend", env=env, check=True)


def start(port: int, api_port: int) -> None:
    existing = running_state()
    if existing:
        print(f"Already running at http://127.0.0.1:{existing['port']}" if healthy(existing)
              else "Local services are starting or unhealthy; use status/stop before starting again")
        return
    if port == api_port:
        raise RuntimeError("Frontend and API ports must be different")
    check_port(port)
    check_port(api_port)
    env = environment(port, api_port)
    prepare(env)
    run_id = secrets.token_hex(16)
    with (LOCAL / "supervisor.log").open("a") as log:
        process = subprocess.Popen([str(PYTHON), str(SCRIPT), "_serve", run_id, str(port), str(api_port)],
                                   cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Local startup failed; inspect .local/supervisor.log and .local/*.log")
        state = running_state()
        if state.get("run_id") == run_id and healthy(state):
            print(f"Dashboard: http://127.0.0.1:{port}")
            print("Login: python3 scripts/local.py credentials")
            print("Demo data: python3 scripts/local.py seed")
            print("Stop: python3 scripts/local.py stop (data is preserved)")
            return
        time.sleep(0.3)
    process.terminate()
    process.wait(timeout=20)
    raise RuntimeError("Startup timed out; inspect .local/*.log")


def serve(run_id: str, port: int, api_port: int) -> None:
    import fcntl
    with (LOCAL / "server.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another local supervisor is already running")
        children: list[subprocess.Popen] = []
        stopping = False

        def shutdown(*_):
            nonlocal stopping
            stopping = True

        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)
        state = {"pid": os.getpid(), "run_id": run_id, "port": port, "api_port": api_port, "ready": False}
        save_json(LOCAL / "run.json", state)
        env = environment(port, api_port)
        try:
            # Fresh local schema; no existing legacy database is stamped or replaced.
            subprocess.run([str(PYTHON), "-m", "alembic", "upgrade", "head"],
                           cwd=ROOT / "backend", env=env, check=True)
            commands = [
                ("backend", [str(PYTHON), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(api_port)], ROOT / "backend"),
                ("worker", [str(PYTHON), "-m", "app.notifications.worker"], ROOT / "backend"),
                ("frontend", [shutil.which("node"), str(ROOT / "frontend/.next/standalone/server.js")], ROOT / "frontend"),
            ]
            for name, command, directory in commands:
                if stopping:
                    return
                with (LOCAL / f"{name}.log").open("a") as log:
                    children.append(subprocess.Popen(command, cwd=directory, env=env,
                                                     stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT))
            state["ready"] = True
            save_json(LOCAL / "run.json", state)
            while not stopping:
                if any(child.poll() is not None for child in children):
                    raise RuntimeError("A local service exited; inspect .local/*.log and restart")
                time.sleep(0.3)
        finally:
            for child in children:
                if child.poll() is None:
                    child.terminate()
            for child in children:
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            if read_json(LOCAL / "run.json").get("run_id") == run_id:
                (LOCAL / "run.json").unlink(missing_ok=True)


def stop() -> None:
    state = running_state()
    if not state:
        print("Local services are stopped; saved data and credentials are preserved")
        return
    os.kill(state["pid"], signal.SIGTERM)
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if not running_state():
            print("Local services stopped; saved data and credentials are preserved")
            return
        time.sleep(0.3)
    raise RuntimeError("Supervisor did not stop cleanly; inspect .local/*.log")


def seed() -> None:
    state = running_state()
    if not state or not healthy(state):
        raise RuntimeError("Start the local dashboard before importing demo data")
    auth = credentials()
    base = f"http://127.0.0.1:{state['port']}"
    token = base64.b64encode(f"{auth['DASHBOARD_USERNAME']}:{auth['DASHBOARD_PASSWORD']}".encode()).decode()
    headers = {"Authorization": f"Basic {token}", "Origin": base}
    findings = request_json(base + "/api/findings?project=demo", headers=headers)
    if findings["count"]:
        print("Project demo already has findings; no data changed")
        return
    result = request_json(base + "/api/import/scan", headers=headers, body={
        "parser": "generic-json", "filename": "demo-scan.json", "project": "demo",
        "content": (ROOT / "examples/demo-scan.json").read_text(),
    })
    print(f"Imported {result['imported']} synthetic demo findings. Open {base}/findings")


def main() -> int:
    if os.name != "posix":
        print("Use macOS, Linux, or Windows with WSL2 for this helper", file=sys.stderr)
        return 1
    os.umask(0o077)
    LOCAL.mkdir(mode=0o700, exist_ok=True)
    LOCAL.chmod(0o700)
    if len(sys.argv) > 1 and sys.argv[1] == "_serve":
        serve(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start_parser = commands.add_parser("start", help="Install, build, migrate and start local services")
    start_parser.add_argument("--port", type=int, default=5050)
    start_parser.add_argument("--api-port", type=int, default=8000)
    for command, help_text in (("status", "Check local services"), ("stop", "Stop services and preserve data"),
                               ("credentials", "Show the dashboard login in your terminal"),
                               ("seed", "Import synthetic example findings once")):
        commands.add_parser(command, help=help_text)
    args = parser.parse_args()
    try:
        import fcntl
        with (LOCAL / "control.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if args.command == "start":
                if not all(1024 <= port <= 65535 for port in (args.port, args.api_port)):
                    raise RuntimeError("Ports must be between 1024 and 65535")
                start(args.port, args.api_port)
            elif args.command == "stop":
                stop()
            elif args.command == "seed":
                seed()
            elif args.command == "status":
                state = running_state()
                if not state:
                    print("Local services are stopped")
                    return 1
                ok = healthy(state)
                print(f"{'Healthy' if ok else 'Starting or unhealthy'}: http://127.0.0.1:{state['port']}")
                print(f"Data and logs: {LOCAL}")
                return 0 if ok else 1
            elif args.command == "credentials":
                if not (LOCAL / "env.json").exists():
                    raise RuntimeError("Run start to create your local credentials")
                if not sys.stdout.isatty():
                    print(f"Run this command in your terminal to see the login, or open {LOCAL / 'env.json'}")
                else:
                    auth = credentials()
                    print(f"Username: {auth['DASHBOARD_USERNAME']}\nPassword: {auth['DASHBOARD_PASSWORD']}")
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        # URLs, database connection strings, and subprocess environment values are
        # never included in commands or diagnostic messages here.
        print(f"Local setup failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
