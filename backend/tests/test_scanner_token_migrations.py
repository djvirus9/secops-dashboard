"""Additive scanner credential migration checks in disposable databases."""
from datetime import timedelta
import hashlib

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.accounts import utcnow
from app.models import AuditEvent, SavedView, ScannerToken, User, UserSession
from test_migrations import migration_engine, upgrade, downgrade


def test_scanner_migration_preserves_existing_accounts_sessions_and_views(migration_engine):
    upgrade(migration_engine, "0004")
    with Session(migration_engine) as db:
        user = User(username="synthetic", password_hash="synthetic-hash", role="admin")
        db.add(user)
        db.flush()
        db.add_all([
            UserSession(user_id=user.id, token_hash="a" * 64, expires_at=utcnow() + timedelta(days=1)),
            SavedView(user_id=user.id, name="Preserved view", filters_json='{"project":"repo-a"}'),
            AuditEvent(user_id=user.id, actor=user.username, action="synthetic", object_type="user"),
        ])
        db.commit()
    metadata = sa.MetaData()
    metadata.reflect(migration_engine)
    tables = [table for table in metadata.sorted_tables if table.name != "alembic_version"]
    with migration_engine.connect() as connection:
        before = {table.name: connection.execute(sa.select(table).order_by(*table.primary_key)).mappings().all()
                  for table in tables}

    upgrade(migration_engine, "0005")

    with migration_engine.connect() as connection:
        for table in tables:
            assert connection.execute(sa.select(table).order_by(*table.primary_key)).mappings().all() == before[table.name]
        assert connection.execute(sa.select(sa.func.count()).select_from(ScannerToken)).scalar_one() == 0
    columns = sa.inspect(migration_engine).get_columns("scanner_tokens")
    assert {column["name"] for column in columns} == set(ScannerToken.__table__.columns.keys())
    assert "token" not in {column["name"] for column in columns}
    indices = sa.inspect(migration_engine).get_indexes("scanner_tokens")
    assert any(index["unique"] and index["column_names"] == ["token_hash"] for index in indices)


def test_scanner_hash_unique_and_occupied_downgrade_refuses_data_loss(migration_engine):
    upgrade(migration_engine, "0005")
    digest = hashlib.sha256(b"synthetic-not-a-real-credential").hexdigest()
    with Session(migration_engine) as db:
        row = ScannerToken(name="Synthetic", project="repo-a", token_hash=digest,
                           expires_at=utcnow() + timedelta(days=1))
        db.add(row)
        db.commit()
        db.add(ScannerToken(name="Duplicate", project="repo-b", token_hash=digest,
                            expires_at=utcnow() + timedelta(days=1)))
        with pytest.raises(sa.exc.IntegrityError):
            db.commit()
        db.rollback()
    with pytest.raises(RuntimeError, match="scanner_tokens contains data"):
        downgrade(migration_engine, "0004")
    with migration_engine.connect() as connection:
        assert connection.execute(sa.text("SELECT version_num FROM alembic_version")).scalar_one() == "0005"
        assert connection.execute(sa.select(ScannerToken.token_hash)).scalar_one() == digest


def test_empty_scanner_migration_can_be_reversed_without_touching_users(migration_engine):
    upgrade(migration_engine, "0005")
    with Session(migration_engine) as db:
        db.add(User(username="preserved", password_hash="synthetic-hash", role="admin"))
        db.commit()
    downgrade(migration_engine, "0004")
    assert "scanner_tokens" not in sa.inspect(migration_engine).get_table_names()
    with Session(migration_engine) as db:
        assert db.scalar(sa.select(User.username)) == "preserved"
    upgrade(migration_engine, "0005")
    assert "scanner_tokens" in sa.inspect(migration_engine).get_table_names()
