"""Backup/restore regression checks with a fake Docker CLI and synthetic archives."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, re, sys
with open(os.environ["TEST_DOCKER_LOG"], "a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\n")
command = " ".join(sys.argv[1:])
if "pg_dump" in command:
    sys.stdout.write("synthetic-backup")
elif "to_regclass" in command:
    print("f" if os.environ.get("TEST_LEGACY") else "t")
elif "SELECT (SELECT count(*) FROM findings)" in command:
    print("1:2")
elif "SELECT count(*) FROM public." in command:
    table = re.search(r"SELECT count\(\*\) FROM public\.([a-z_]+)", command).group(1)
    print(2 if table == "intelligence_sync_states" else
          0 if table in {"github_sync_runs", "github_alerts", "vulnerability_intelligence",
                         "jira_issue_links", "jira_user_mappings", "jira_sync_control", "operational_alerts"} else 1)
'''


class BackupRestoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="secops-infra-tests-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        executable = self.directory / "docker"
        executable.write_text(FAKE_DOCKER)
        executable.chmod(0o700)
        self.log = self.directory / "docker.jsonl"
        self.env = {"PATH": str(self.directory) + os.pathsep + os.environ["PATH"],
                    "TEST_DOCKER_LOG": str(self.log), "SECOPS_ENV_FILE": str(self.directory / "private env"),
                    "SECOPS_COMPOSE_FILE": str(ROOT / "infra/docker-compose.images.yml")}
        self.archive = self.directory / "synthetic archive.dump"

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def run_script(self, name, **env):
        return subprocess.run(["bash", str(ROOT / "infra" / name), str(self.archive)],
                              env={**self.env, **env}, capture_output=True, text=True, timeout=10)

    def test_backup_and_restore_use_selected_compose_without_replacing_a_backup(self):
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        self.assertEqual(self.archive.read_text(), "synthetic-backup")
        self.assertEqual(self.archive.stat().st_mode & 0o777, 0o600)
        result = self.run_script("verify-restore.sh", SECOPS_EXPECTED_FINDINGS="1", SECOPS_EXPECTED_COMMENTS="2",
                                 SECOPS_EXPECTED_SCANNER_TOKENS="1", SECOPS_EXPECTED_GITHUB_CONNECTIONS="1",
                                 SECOPS_EXPECTED_GITHUB_SYNC_RUNS="0", SECOPS_EXPECTED_GITHUB_ALERTS="0",
                                 SECOPS_EXPECTED_VULNERABILITY_INTELLIGENCE="0",
                                 SECOPS_EXPECTED_REMEDIATION_POLICIES="1",
                                 SECOPS_EXPECTED_INTELLIGENCE_SYNC_STATES="2",
                                 SECOPS_EXPECTED_TEAMS="1", SECOPS_EXPECTED_PROJECTS="1",
                                 SECOPS_EXPECTED_COVERAGE_EXPECTATIONS="1", SECOPS_EXPECTED_TEAM_MEMBERSHIPS="1",
                                 SECOPS_EXPECTED_OWNERSHIP_RULES="1", SECOPS_EXPECTED_AUTOMATION_POLICIES="1",
                                 SECOPS_EXPECTED_JIRA_ISSUE_LINKS="0", SECOPS_EXPECTED_JIRA_USER_MAPPINGS="0",
                                 SECOPS_EXPECTED_JIRA_SYNC_CONTROL="0", SECOPS_EXPECTED_OPERATIONAL_ALERTS="0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.run_script("backup.sh").returncode, 1)
        for call in self.calls():
            self.assertEqual(call[call.index("-f") + 1], self.env["SECOPS_COMPOSE_FILE"])
            self.assertEqual(call[call.index("--env-file") + 1], self.env["SECOPS_ENV_FILE"])
        self.assertTrue(any("dropdb" in " ".join(call) for call in self.calls()))
        self.assertIn("Restored team_memberships: 1 (table present: t)", result.stdout)
        self.assertIn("Restored operational_alerts: 0 (table present: t)", result.stdout)

    def test_older_backup_missing_new_tables_restores_and_does_not_query_absent_rows(self):
        self.archive.write_text("synthetic old backup")
        result = self.run_script("verify-restore.sh", TEST_LEGACY="1", SECOPS_EXPECTED_SCANNER_TOKENS="0",
                                 SECOPS_EXPECTED_GITHUB_CONNECTIONS="0", SECOPS_EXPECTED_TEAMS="0",
                                 SECOPS_EXPECTED_TEAM_MEMBERSHIPS="0", SECOPS_EXPECTED_AUTOMATION_POLICIES="0",
                                 SECOPS_EXPECTED_JIRA_SYNC_CONTROL="0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("table present: f", result.stdout)
        self.assertFalse(any("SELECT count(*) FROM public." in " ".join(call) for call in self.calls()))
        self.assertTrue(any("dropdb" in " ".join(call) for call in self.calls()))

    def test_operations_count_mismatch_still_cleans_up_only_temporary_restore_database(self):
        self.archive.write_text("synthetic backup")
        result = self.run_script("verify-restore.sh", SECOPS_EXPECTED_OWNERSHIP_RULES="2")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Restored ownership_rules count does not match", result.stderr)
        deletes = [call for call in self.calls() if "dropdb" in " ".join(call)]
        self.assertEqual(len(deletes), 1)
        self.assertTrue(deletes[0][-1].startswith("secops_restore_check_"))

    def test_invalid_operations_expected_counts_are_rejected_before_docker(self):
        self.archive.write_text("synthetic backup")
        for key in ("TEAMS", "PROJECTS", "COVERAGE_EXPECTATIONS", "TEAM_MEMBERSHIPS", "OWNERSHIP_RULES",
                    "JIRA_ISSUE_LINKS", "JIRA_USER_MAPPINGS", "JIRA_SYNC_CONTROL", "AUTOMATION_POLICIES",
                    "OPERATIONAL_ALERTS"):
            with self.subTest(key=key):
                result = self.run_script("verify-restore.sh", **{f"SECOPS_EXPECTED_{key}": "-1"})
                self.assertEqual(result.returncode, 1)
                self.assertIn("Expected restore row counts must be nonnegative integers", result.stderr)
                self.assertFalse(self.log.exists())

    def test_failed_count_check_still_removes_only_temporary_restore_database(self):
        self.archive.write_text("synthetic backup")
        result = self.run_script("verify-restore.sh", SECOPS_EXPECTED_SCANNER_TOKENS="99")
        self.assertEqual(result.returncode, 1)
        deletes = [call for call in self.calls() if "dropdb" in " ".join(call)]
        self.assertEqual(len(deletes), 1)
        self.assertTrue(deletes[0][-1].startswith("secops_restore_check_"))
        self.assertEqual(self.archive.read_text(), "synthetic backup")


if __name__ == "__main__":
    unittest.main()
