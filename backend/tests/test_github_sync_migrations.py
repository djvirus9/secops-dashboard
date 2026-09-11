"""The GitHub migration adds tables without rewriting application data."""
from datetime import timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.github_sync.models import GitHubConnection
from app.models import Finding, ScannerToken, User, _utcnow
from test_migrations import migration_engine, upgrade, downgrade


def test_github_migration_preserves_existing_findings_users_and_scanner_credentials(migration_engine):
    upgrade(migration_engine, "0005")
    with Session(migration_engine) as db:
        db.add_all([
            User(username="synthetic-admin", password_hash="unchanged-password-hash", role="admin"),
            ScannerToken(name="Existing scanner", project="one", token_hash="b" * 64,
                         expires_at=_utcnow() + timedelta(days=1)),
            Finding(fingerprint="a" * 64, tool="synthetic", project="one", title="Preserved triage",
                    severity="high", asset="synthetic.invalid", status="investigating", assignee="alice",
                    signal_id="synthetic-signal", occurrences=8),
        ])
        db.commit()
    metadata = sa.MetaData()
    metadata.reflect(migration_engine)
    tables = [table for table in metadata.sorted_tables if table.name != "alembic_version"]
    with migration_engine.connect() as connection:
        before = {table.name: connection.execute(sa.select(table).order_by(*table.primary_key)).mappings().all()
                  for table in tables}
    upgrade(migration_engine, "head")
    with migration_engine.connect() as connection:
        for table in tables:
            assert connection.execute(sa.select(table).order_by(*table.primary_key)).mappings().all() == before[table.name]
        for name in ("github_connections", "github_sync_runs", "github_alerts"):
            table = sa.Table(name, sa.MetaData(), autoload_with=connection)
            assert connection.execute(sa.select(sa.func.count()).select_from(table)).scalar_one() == 0


def test_github_identity_is_unique_and_populated_downgrade_refuses_before_ddl(migration_engine):
    upgrade(migration_engine)
    with Session(migration_engine) as db:
        db.add(GitHubConnection(repository="fixture/repo", project="one", sources_json='["dependabot"]'))
        db.commit()
        db.add(GitHubConnection(repository="fixture/repo", project="two", sources_json='["code_scanning"]'))
        with pytest.raises(sa.exc.IntegrityError):
            db.commit()
        db.rollback()
    before = set(sa.inspect(migration_engine).get_table_names())
    with pytest.raises(RuntimeError, match="github_connections contains data"):
        downgrade(migration_engine, "0005")
    assert set(sa.inspect(migration_engine).get_table_names()) == before
    with migration_engine.connect() as connection:
        assert connection.execute(sa.text("SELECT version_num FROM alembic_version")).scalar_one() == "0006"
