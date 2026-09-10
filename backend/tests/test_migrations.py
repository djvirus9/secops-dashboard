from __future__ import annotations

from datetime import datetime
import importlib.util
import os
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
import sqlalchemy as sa

from app.adopt_legacy_db import (
    LegacySchemaError,
    adopt_legacy_database,
    validate_legacy_schema,
)
from app.db import Base

BACKEND_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(params=["sqlite", "postgresql"])
def migration_engine(request, tmp_path):
    if request.param == "sqlite":
        engine = sa.create_engine(f"sqlite:///{tmp_path / 'migration.db'}")
        yield engine
        engine.dispose()
        return
    test_url = os.environ.get("TEST_DATABASE_URL", "")
    if not test_url or sa.engine.make_url(test_url).get_backend_name() != "postgresql":
        pytest.skip("PostgreSQL migration checks require the dedicated TEST_DATABASE_URL")
    # Each migration scenario gets a disposable schema in the explicitly
    # configured test database. Never inspect or mutate a real application DB.
    admin = sa.create_engine(test_url)
    schema = f"migration_test_{uuid4().hex}"
    with admin.begin() as connection:
        connection.execute(sa.schema.CreateSchema(schema))
    engine = sa.create_engine(test_url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as connection:
            connection.execute(sa.schema.DropSchema(schema, cascade=True))
        admin.dispose()


def upgrade(engine, revision="head"):
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, revision)


def legacy_schema(engine, variant="initial"):
    reference = sa.create_engine("sqlite://")
    spec = importlib.util.spec_from_file_location(
        "original_schema_fixture", BACKEND_ROOT / "migrations/versions/0001_initial_schema.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    metadata = sa.MetaData()
    with reference.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            module.upgrade()
        metadata.reflect(connection)
    reference.dispose()
    for table in metadata.tables.values():
        for column in table.columns:
            column.type = column.type.as_generic()
    if variant == "orm":
        for table in metadata.tables.values():
            for column in table.columns:
                column.server_default = None
        assets = metadata.tables["assets"]
        for constraint in list(assets.constraints):
            if isinstance(constraint, sa.UniqueConstraint):
                assets.constraints.remove(constraint)
        for index in assets.indexes:
            if index.name == "ix_assets_key":
                index.unique = True
    metadata.create_all(engine)


def seed_legacy_rows(engine):
    metadata = sa.MetaData()
    metadata.reflect(engine)
    now = datetime(2026, 1, 20, 12)
    with engine.begin() as connection:
        connection.execute(metadata.tables["assets"].insert(), {
            "id": "asset-a", "key": "service.internal", "name": "Service",
            "environment": "prod", "owner": "Security", "criticality": "high",
            "exposure": "internal", "created_at": now, "updated_at": now,
        })
        connection.execute(metadata.tables["signals"].insert(), {
            "id": "signal-a", "tool": "semgrep", "payload": "{}", "created_at": now,
        })
        common = {
            "fingerprint": "a" * 64, "tool": "semgrep", "title": "Existing finding",
            "severity": "high", "asset": "service.internal", "asset_id": "asset-a",
            "exposure": "internal", "criticality": "high", "status": "investigating",
            "assignee": "Security", "risk_score": 130, "description": "Preserve evidence",
            "first_seen": now, "last_seen": now, "signal_id": "signal-a",
        }
        connection.execute(metadata.tables["findings"].insert(), [
            {**common, "id": "finding-a", "occurrences": 2},
            {**common, "id": "finding-b", "occurrences": 3},
        ])
        connection.execute(metadata.tables["comments"].insert(), {
            "id": "comment-a", "finding_id": "finding-b", "author": "Analyst",
            "content": "Keep the investigation history", "created_at": now,
        })


def test_fresh_migrations_match_current_models(migration_engine):
    upgrade(migration_engine)
    with migration_engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []


@pytest.mark.parametrize("variant", ["initial", "orm"])
def test_adoption_and_full_upgrade_preserve_legacy_data(migration_engine, variant):
    legacy_schema(migration_engine, variant)
    seed_legacy_rows(migration_engine)
    with migration_engine.connect() as connection:
        validate_legacy_schema(connection)
        assert "alembic_version" not in sa.inspect(connection).get_table_names()
    adopt_legacy_database(migration_engine, backup_acknowledged=True)
    with migration_engine.connect() as connection:
        assert connection.execute(sa.text("SELECT version_num FROM alembic_version")).scalar_one() == "0001"
    upgrade(migration_engine)
    with migration_engine.connect() as connection:
        finding = connection.execute(sa.text("SELECT * FROM findings")).mappings().one()
        assert finding["id"] == "finding-a"
        assert finding["fingerprint"] == "a" * 64
        assert finding["occurrences"] == 5
        assert finding["description"] == "Preserve evidence"
        assert finding["status"] == "investigating"
        assert finding["assignee"] == "Security"
        assert finding["project"] == ""
        assert finding["references_json"] == "[]"
        comment = connection.execute(sa.text("SELECT * FROM comments")).mappings().one()
        assert comment["finding_id"] == "finding-a"
        assert comment["content"] == "Keep the investigation history"
        assert connection.execute(sa.text("SELECT owner FROM assets")).scalar_one() == "Security"
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []


def test_adoption_requires_backup_acknowledgement(migration_engine):
    legacy_schema(migration_engine)
    with pytest.raises(LegacySchemaError, match="backup"):
        adopt_legacy_database(migration_engine, backup_acknowledged=False)
    assert "alembic_version" not in sa.inspect(migration_engine).get_table_names()


@pytest.mark.parametrize("change", ["extra_column", "missing_index", "extra_table"])
def test_unknown_legacy_schema_is_refused_without_stamping(migration_engine, change):
    legacy_schema(migration_engine)
    with migration_engine.begin() as connection:
        if change == "extra_column":
            connection.exec_driver_sql("ALTER TABLE findings ADD COLUMN unknown_evidence TEXT")
        elif change == "missing_index":
            connection.exec_driver_sql("DROP INDEX ix_findings_fingerprint")
        else:
            connection.exec_driver_sql("CREATE TABLE unknown_data (id INTEGER)")
    with pytest.raises(LegacySchemaError):
        adopt_legacy_database(migration_engine, backup_acknowledged=True)
    assert "alembic_version" not in sa.inspect(migration_engine).get_table_names()


def test_versioned_database_is_not_eligible_for_adoption(migration_engine):
    upgrade(migration_engine, "0001")
    with pytest.raises(LegacySchemaError):
        adopt_legacy_database(migration_engine, backup_acknowledged=True)


def test_changed_timestamp_semantics_are_not_adopted(migration_engine):
    if migration_engine.dialect.name != "postgresql":
        pytest.skip("SQLite does not preserve timestamp timezone type semantics")
    legacy_schema(migration_engine)
    with migration_engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE findings ALTER COLUMN first_seen TYPE TIMESTAMPTZ")
    with pytest.raises(LegacySchemaError):
        adopt_legacy_database(migration_engine, backup_acknowledged=True)
    assert "alembic_version" not in sa.inspect(migration_engine).get_table_names()


def test_percent_encoded_database_url_does_not_break_migration_configuration(migration_engine, monkeypatch):
    # The supplied migration connection is local. The synthetic URL is parsed
    # by Alembic's config only and is never contacted.
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:p%40ss%25word@unused.invalid/db")
    upgrade(migration_engine)
    assert "findings" in sa.inspect(migration_engine).get_table_names()
