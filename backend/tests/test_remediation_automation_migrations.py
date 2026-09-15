"""v0.6 upgrades preserve data and downgrade refusal performs no partial DDL."""
from uuid import uuid4

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.automation.models import AutomationPolicy, OperationalAlert
from app.db import Base
from app.jira_sync.models import JiraIssueLink, JiraSyncControl, JiraUserMapping
from app.models import (
    Asset, Finding, OwnershipRule, ProjectProfile, RemediationPolicy, Team,
    TeamMembership, User, VulnerabilityIntelligence,
)
from test_migrations import migration_engine, upgrade, downgrade


def finding(**kwargs):
    return Finding(fingerprint=uuid4().hex, tool="synthetic", title="Preserve fixture",
                   severity="high", asset="example.invalid", signal_id=str(uuid4()), **kwargs)


def snapshot(engine):
    metadata = sa.MetaData()
    metadata.reflect(engine)
    with engine.connect() as connection:
        return {table.name: (tuple(table.columns.keys()),
                            connection.execute(sa.select(table).order_by(*table.primary_key)).mappings().all())
                for table in metadata.sorted_tables}


def assert_refusal_is_read_only(engine, target, match="Cannot downgrade"):
    before = snapshot(engine)
    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.strip().upper())

    sa.event.listen(engine, "before_cursor_execute", record)
    try:
        with pytest.raises(RuntimeError, match=match):
            downgrade(engine, target)
    finally:
        sa.event.remove(engine, "before_cursor_execute", record)
    assert statements
    assert not any(sql.startswith(("CREATE ", "ALTER ", "DROP ", "INSERT ", "UPDATE ", "DELETE ")) for sql in statements)
    assert snapshot(engine) == before


def test_v06_additive_upgrade_preserves_all_v05_rows_and_matches_models(migration_engine):
    upgrade(migration_engine, "0008")
    with Session(migration_engine) as db:
        user = User(username="preserved", password_hash="synthetic-hash", role="analyst", projects_json='["payments"]')
        team = Team(name="Preserved owning team")
        db.add_all([user, team, finding(project="payments", status="verification_pending", assignee="legacy-owner")])
        db.flush()
        db.add(ProjectProfile(name="payments", team_id=team.id))
        db.commit()
    before = snapshot(migration_engine)
    upgrade(migration_engine, "head")
    after = snapshot(migration_engine)
    for name, rows in before.items():
        if name != "alembic_version":
            assert after[name] == rows
    for name in ("ownership_rules", "team_memberships", "jira_issue_links", "jira_user_mappings",
                 "jira_sync_control", "automation_policies", "operational_alerts"):
        assert after[name][1] == []
    with migration_engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == "0011"


@pytest.mark.parametrize("revision", ["0009", "0010", "0011"])
def test_each_v06_revision_refuses_before_ddl_when_older_identity_guard_would_fail(migration_engine, revision):
    upgrade(migration_engine, revision)
    with Session(migration_engine) as db:
        db.add(User(username="keep", password_hash="synthetic-hash", role="admin"))
        db.commit()
    assert_refusal_is_read_only(migration_engine, "0003", "users contains data")


@pytest.mark.parametrize("populated,match", [
    ("ownership", "ownership_rules contains data"),
    ("membership", "team_memberships contains data"),
    ("jira_link", "jira_issue_links contains data"),
    ("jira_mapping", "jira_user_mappings contains data"),
    ("jira_lease", "a Jira sync is running"),
    ("automation", "automation_policies contains data"),
    ("alert", "operational_alerts contains data"),
])
def test_populated_v06_lifecycle_refuses_entire_downgrade_before_any_schema_changes(migration_engine, populated, match):
    upgrade(migration_engine)
    with Session(migration_engine) as db:
        if populated == "ownership":
            db.add(ProjectProfile(name="payments"))
            db.flush()
            db.add(OwnershipRule(project="payments", enabled=False))
        elif populated == "membership":
            team, user = Team(name="Keep"), User(username="keep", password_hash="synthetic-hash", role="analyst")
            db.add_all([team, user])
            db.flush()
            db.add(TeamMembership(team_id=team.id, user_id=user.id))
        elif populated == "jira_link":
            row = finding()
            db.add(row)
            db.flush()
            db.add(JiraIssueLink(finding_id=row.id, issue_key="SEC-1", base_url="https://synthetic.atlassian.net"))
        elif populated == "jira_mapping":
            user = User(username="keep", password_hash="synthetic-hash", role="analyst")
            db.add(user)
            db.flush()
            db.add(JiraUserMapping(user_id=user.id, jira_account_id="synthetic-account"))
        elif populated == "jira_lease":
            db.add(JiraSyncControl(id=1, claim_token="active-lease"))
        elif populated == "automation":
            db.add(AutomationPolicy(project="payments"))
        else:
            db.add(OperationalAlert(project="payments", kind="coverage", resource_id=str(uuid4()),
                                    condition="stale", title="Preserve alert", message="Synthetic evidence"))
        db.commit()
    assert_refusal_is_read_only(migration_engine, "0003", match)


@pytest.mark.parametrize("populated,match", [
    ("verified_by", "structured remediation workflow"),
    ("priority", "remediation intelligence has been applied"),
    ("intelligence", "vulnerability intelligence is cached"),
    ("project_policy", "project remediation policies exist"),
    ("shared_assets", "asset keys are shared across projects"),
])
def test_v06_preflight_preserves_older_workflow_and_metadata_guards(migration_engine, populated, match):
    upgrade(migration_engine)
    with Session(migration_engine) as db:
        if populated == "verified_by":
            db.add(finding(verified_by="historical-verifier"))
        elif populated == "priority":
            db.add(finding(priority_score=88))
        elif populated == "intelligence":
            db.add(VulnerabilityIntelligence(cve_id="CVE-2026-12345"))
        elif populated == "project_policy":
            db.add(RemediationPolicy(project="payments"))
        else:
            db.add_all([Asset(project="payments", key="shared"), Asset(project="identity", key="shared")])
        db.commit()
    assert_refusal_is_read_only(migration_engine, "0002", match)


@pytest.mark.parametrize("revision", ["0009", "0010", "0011"])
def test_empty_v06_downgrade_and_reupgrade(migration_engine, revision):
    upgrade(migration_engine, revision)
    downgrade(migration_engine, "0008")
    assert set(sa.inspect(migration_engine).get_table_names()).isdisjoint({
        "ownership_rules", "team_memberships", "jira_issue_links", "jira_user_mappings",
        "jira_sync_control", "automation_policies", "operational_alerts",
    })
    upgrade(migration_engine)
    with migration_engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
