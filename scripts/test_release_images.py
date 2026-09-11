"""Verify publication gates without contacting GitHub or a registry."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("release_images_under_test", Path(__file__).with_name("release_images.py"))
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
SHA = "a" * 40


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        (root / "frontend").mkdir()
        (root / "pyproject.toml").write_text('[project]\nversion = "0.3.0"\n')
        (root / "frontend/package.json").write_text(json.dumps({"version": "0.3.0"}))
        for context in (patch.object(release, "__file__", str(root / "scripts/release_images.py")),
                        patch.object(release.subprocess, "check_output", return_value=SHA + "\n"),
                        patch.dict(os.environ, {"GITHUB_REPOSITORY": release.REPOSITORY,
                                                "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": SHA})):
            context.start()
            self.addCleanup(context.stop)

    def response(self, path, **_):
        if "git/ref/heads/main" in path:
            return {"object": {"sha": SHA}}
        if "/workflows/" in path:
            return {"workflow_runs": [{"id": 1 if "ci.yml" in path else 2, "head_sha": SHA,
                    "head_branch": "main", "event": "push", "run_number": 1, "run_attempt": 1,
                    "status": "completed", "conclusion": "success"}]}
        if "/jobs?" in path:
            names = release.REQUIRED["ci.yml" if "/runs/1/" in path else "codeql.yml"]
            return {"jobs": [{"name": name, "status": "completed", "conclusion": "success"} for name in names]}
        return None

    def test_success_requires_both_postmerge_workflows(self):
        with patch.object(release, "api", side_effect=self.response) as api:
            release.verify("v0.3.0", SHA)
        self.assertTrue(any("codeql.yml" in call.args[0] for call in api.call_args_list))

    def test_invalid_input_and_non_main_never_contact_github(self):
        for version, commit in (("v0.3.0; echo unsafe", SHA), ("v0.3.0", "main"), ("v0.3.1", SHA)):
            with self.subTest(version=version), patch.object(release, "api") as api:
                with self.assertRaises(RuntimeError):
                    release.verify(version, commit)
                api.assert_not_called()
        with patch.dict(os.environ, {"GITHUB_REF": "refs/pull/1/merge"}), patch.object(release, "api") as api:
            with self.assertRaises(RuntimeError):
                release.verify("v0.3.0", SHA)
            api.assert_not_called()

    def test_stale_commit_failed_or_missing_jobs_and_existing_tag_are_rejected(self):
        for failure in ("stale", "failed", "skipped", "retag"):
            def response(path, **kwargs):
                value = self.response(path, **kwargs)
                if failure == "stale" and "git/ref/heads/main" in path:
                    value["object"]["sha"] = "b" * 40
                if failure == "failed" and "/workflows/" in path:
                    value["workflow_runs"][0]["conclusion"] = "failure"
                if failure == "skipped" and "/jobs?" in path:
                    value["jobs"][0]["conclusion"] = "skipped"
                if failure == "retag" and "/packages/" in path:
                    return [{"metadata": {"container": {"tags": ["v0.3.0"]}}}]
                return value
            with self.subTest(failure=failure), patch.object(release, "api", side_effect=response):
                with self.assertRaises(RuntimeError):
                    release.verify("v0.3.0", SHA)

    def test_checked_out_commit_must_match_dispatch(self):
        with patch.object(release.subprocess, "check_output", return_value="b" * 40), patch.object(release, "api") as api:
            with self.assertRaisesRegex(RuntimeError, "Checked-out code"):
                release.verify("v0.3.0", SHA)
            api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
