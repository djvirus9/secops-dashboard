#!/usr/bin/env python3
"""Read-only release gate. Called only by the manually dispatched image workflow."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib
from urllib.error import HTTPError
from urllib.request import Request, urlopen

REPOSITORY = "djvirus9/secops-dashboard"
IMAGES = ("secops-dashboard-backend", "secops-dashboard-frontend")
REQUIRED = {
    "ci.yml": {"backend (3.12)", "backend (3.14)", "frontend", "frontend (Node 26)", "containers"},
    "codeql.yml": {"Analyze python", "Analyze javascript-typescript"},
}


def api(path: str, *, missing_ok: bool = False):
    request = Request("https://api.github.com" + path, headers={
        "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10",
    })
    try:
        with urlopen(request, timeout=30) as response:
            return json.load(response)
    except HTTPError as error:
        if missing_ok and error.code == 404:
            return None
        raise RuntimeError(f"GitHub release verification failed (HTTP {error.code})") from None


def verify(version: str, commit: str) -> None:
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version):
        raise RuntimeError("Version must be a stable vMAJOR.MINOR.PATCH tag")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError("Commit must be a complete lowercase SHA")
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise RuntimeError("Publish only from the upstream main branch")
    if os.environ.get("GITHUB_SHA") != commit:
        raise RuntimeError("Dispatch main at the exact commit being released")
    root = Path(__file__).resolve().parents[1]
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if actual != commit:
        raise RuntimeError("Checked-out code does not match the release commit")
    python_version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    frontend_version = json.loads((root / "frontend/package.json").read_text())["version"]
    if python_version != version[1:] or frontend_version != version[1:]:
        raise RuntimeError("Release version must match both package manifests")
    current = api(f"/repos/{REPOSITORY}/git/ref/heads/main")["object"]["sha"]
    if current != commit:
        raise RuntimeError("The selected commit is no longer main; verify the new main before publishing")
    for workflow, expected in REQUIRED.items():
        runs = api(f"/repos/{REPOSITORY}/actions/workflows/{workflow}/runs?head_sha={commit}&event=push&per_page=100")["workflow_runs"]
        runs = [run for run in runs if run["head_sha"] == commit and run["head_branch"] == "main" and run["event"] == "push"]
        if not runs:
            raise RuntimeError(f"Missing post-merge {workflow} run")
        latest = max(runs, key=lambda run: (run["run_number"], run.get("run_attempt", 1)))
        if latest["status"] != "completed" or latest["conclusion"] != "success":
            raise RuntimeError(f"Latest post-merge {workflow} run must succeed first")
        jobs = api(f"/repos/{REPOSITORY}/actions/runs/{latest['id']}/jobs?filter=latest&per_page=100")["jobs"]
        successful = {job["name"] for job in jobs if job["status"] == "completed" and job["conclusion"] == "success"}
        if not expected.issubset(successful):
            raise RuntimeError(f"Required {workflow} jobs have not all succeeded")
    # Version tags are published only once by this workflow. A registry owner can
    # still retag manually; deployed digest references remain immutable.
    for image in IMAGES:
        for page in range(1, 11):
            versions = api(f"/users/djvirus9/packages/container/{image}/versions?per_page=100&page={page}", missing_ok=True)
            if versions is None:
                break
            if any(version in entry["metadata"]["container"]["tags"] for entry in versions):
                raise RuntimeError(f"Refusing to overwrite existing {image}:{version}")
            if len(versions) < 100:
                break
        else:
            raise RuntimeError("Package history exceeds the release gate's inspection limit")
    print(f"Verified tested main {commit} for {version}; release version tags are unused")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        verify(args.version, args.commit)
    except (RuntimeError, KeyError, OSError, ValueError) as error:
        raise SystemExit(str(error)) from None
