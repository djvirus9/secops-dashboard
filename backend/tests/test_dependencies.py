from __future__ import annotations

import tomllib
from pathlib import Path


def test_python_dependency_manifests_stay_in_sync():
    repository_root = Path(__file__).resolve().parents[2]
    pyproject = tomllib.loads((repository_root / "pyproject.toml").read_text())
    locked_requirements = {
        line.strip().lower()
        for line in (repository_root / "backend" / "requirements.txt")
        .read_text()
        .splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    project_dependencies = {
        dependency.lower() for dependency in pyproject["project"]["dependencies"]
    }

    assert locked_requirements == project_dependencies

    development_requirements = {
        line.strip().lower()
        for line in (repository_root / "backend" / "requirements-dev.txt")
        .read_text()
        .splitlines()
        if line.strip()
        and not line.lstrip().startswith(("#", "-r", "--requirement"))
    }
    development_dependencies = {
        dependency.lower() for dependency in pyproject["dependency-groups"]["dev"]
    }

    assert development_requirements == development_dependencies
