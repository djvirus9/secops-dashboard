"""Validate both Compose modes without printing resolved secrets. Needs Compose v2."""
import json
import subprocess


def config(filename):
    result = subprocess.run(["docker", "compose", "--env-file", "/dev/null", "-f", filename,
                             "config", "--format", "json"], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise SystemExit("Compose configuration did not validate")
    return json.loads(result.stdout)


def main():
    source = config("infra/docker-compose.yml")
    images = config("infra/docker-compose.images.yml")
    expected = {"postgres", "backend", "notification-worker", "github-worker", "intelligence-worker", "frontend"}
    assert set(source["services"]) == set(images["services"]) == expected
    for name in expected:
        original = source["services"][name]
        prebuilt = images["services"][name]
        assert "build" not in prebuilt, "Image deployment must never build from source"
        if name != "postgres":
            assert "build" in original and prebuilt.get("image"), "Every application service needs its selected runtime"
        normalized = lambda service: {key: value for key, value in service.items() if key not in {"build", "image", "pull_policy"}}
        assert normalized(original) == normalized(prebuilt), "Runtime settings drifted between Compose modes"
        env = prebuilt.get("environment", {})
        assert ("GITHUB_SYNC_TOKEN" in env) == (name in {"backend", "github-worker"}), "GitHub token reached an unrelated service"
        if name not in {"backend", "postgres"}:
            assert not {"API_KEY", "INGEST_API_KEY", "DASHBOARD_PASSWORD"} & set(env), \
                "Administrative or browser credentials reached a worker"
        if name == "intelligence-worker":
            assert set(env) == {"PGHOST", "PGUSER", "PGPASSWORD", "PGDATABASE", "INTELLIGENCE_POLL_SECONDS"}, \
                "Intelligence worker received unrelated application or integration credentials"
        if name == "frontend":
            assert set(env) == {"BACKEND_URL", "DASHBOARD_ORIGINS"}, "Frontend runtime must not receive backend credentials"
    print("Source/image Compose parity, build isolation and service credential boundaries passed")


if __name__ == "__main__":
    main()
