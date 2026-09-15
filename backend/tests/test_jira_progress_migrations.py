"""Additive Jira schema and refusal to discard progress/mapping evidence."""
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.jira_sync.models import JiraIssueLink, JiraSyncControl, JiraUserMapping
from app.models import Finding, User
from test_migrations import migration_engine, upgrade, downgrade


def test_jira_upgrade_preserves_prior_schema_rows(migration_engine):
    upgrade(migration_engine, "0009")
    with Session(migration_engine) as db:
        finding = Finding(fingerprint=uuid4().hex, tool="synthetic", project="payments",
                          title="Preserved finding", severity="high", asset="synthetic.invalid",
                          signal_id=str(uuid4()), status="verification_pending", assignee="legacy-owner")
        db.add(finding)
        db.commit()
    metadata = sa.MetaData()
    metadata.reflect(migration_engine)
    tables = [table for table in metadata.sorted_tables if table.name != "alembic_version"]
    with migration_engine.connect() as connection:
        before = {table.name: connection.execute(sa.select(table).order_by(*table.primary_key)).mappings().all()
                  for table in tables}
    upgrade(migration_engine, "0010")
    with migration_engine.connect() as connection:
        for table in tables:
            assert connection.execute(sa.select(table).order_by(*table.primary_key)).mappings().all() == before[table.name]
        for table in (JiraIssueLink.__table__, JiraUserMapping.__table__, JiraSyncControl.__table__):
            assert connection.scalar(sa.select(sa.func.count()).select_from(table)) == 0


@pytest.mark.parametrize("populated", ["link", "mapping", "lease"])
def test_jira_populated_downgrade_refuses_before_ddl(migration_engine, populated):
    upgrade(migration_engine, "0010")
    with Session(migration_engine) as db:
        if populated == "link":
            finding = Finding(fingerprint=uuid4().hex, tool="synthetic", project="payments",
                              title="Preserved finding", severity="high", asset="synthetic.invalid",
                              signal_id=str(uuid4()))
            db.add(finding)
            db.flush()
            db.add(JiraIssueLink(finding_id=finding.id, issue_key="SEC-1", base_url="https://synthetic.atlassian.net"))
        elif populated == "mapping":
            user = User(username="synthetic", password_hash="unused-synthetic-hash", role="analyst")
            db.add(user)
            db.flush()
            db.add(JiraUserMapping(user_id=user.id, jira_account_id="abc:123"))
        else:
            db.add(JiraSyncControl(id=1, claim_token="active-lease"))
        db.commit()
    before = set(sa.inspect(migration_engine).get_table_names())
    with pytest.raises(RuntimeError, match="Cannot downgrade"):
        downgrade(migration_engine, "0009")
    assert set(sa.inspect(migration_engine).get_table_names()) == before
    with migration_engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == "0010"


def test_empty_jira_downgrade_round_trip(migration_engine):
    upgrade(migration_engine, "0010")
    downgrade(migration_engine, "0009")
    assert "jira_issue_links" not in sa.inspect(migration_engine).get_table_names()
    upgrade(migration_engine, "0010")
    assert "jira_issue_links" in sa.inspect(migration_engine).get_table_names()
