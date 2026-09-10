"""Explicitly adopt a verified, unversioned pre-Alembic database at revision 0001.

Validation is read-only. Stamping requires both --adopt and a backup
acknowledgement, and never runs schema upgrades automatically.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from functools import lru_cache
import importlib.util
from pathlib import Path
import re
import sys

from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import Float, create_engine, inspect, text
from sqlalchemy.engine import Connection, Engine


BACKEND_ROOT = Path(__file__).resolve().parents[1]
LEGACY_TABLES = {"assets", "signals", "findings", "comments"}


class LegacySchemaError(ValueError):
    pass


def _default(value):
    if value is None:
        return None
    value = re.sub(r"::(?:character varying|text|integer|numeric)", "", str(value))
    return value.strip("()'")


def _schema(connection: Connection) -> dict:
    inspector = inspect(connection)
    tables = set(inspector.get_table_names())
    if tables != LEGACY_TABLES or inspector.get_view_names():
        raise LegacySchemaError(
            "Expected exactly assets, signals, findings, comments and no views or version table"
        )
    if connection.dialect.name == "sqlite":
        has_triggers = connection.execute(
            text("SELECT 1 FROM sqlite_master WHERE type = 'trigger' LIMIT 1")
        ).first()
    elif connection.dialect.name == "postgresql":
        has_triggers = connection.execute(text(
            "SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE NOT t.tgisinternal AND n.nspname=current_schema() LIMIT 1"
        )).first()
        if inspector.get_materialized_view_names():
            raise LegacySchemaError("Unexpected materialized views")
    else:
        raise LegacySchemaError("Only SQLite and PostgreSQL legacy databases are supported")
    if has_triggers:
        raise LegacySchemaError("Unexpected user-defined database triggers")

    result = {}
    for name in sorted(tables):
        columns = {}
        for column in inspector.get_columns(name):
            generic_type = column["type"].as_generic()
            columns[column["name"]] = (
                "Float" if isinstance(generic_type, Float) else type(generic_type).__name__,
                getattr(generic_type, "length", None),
                bool(column["nullable"]),
                _default(column.get("default")),
                bool(column.get("computed")),
                bool(column.get("identity")),
                getattr(generic_type, "timezone", None),
                None if isinstance(generic_type, Float) else getattr(column["type"], "precision", None),
                getattr(generic_type, "collation", None),
            )
        indexes = sorted(
            (index["name"], tuple(index["column_names"]), bool(index["unique"]),
             any(bool(value) for value in index.get("dialect_options", {}).values()))
            for index in inspector.get_indexes(name)
            if not index.get("duplicates_constraint")
        )
        unique = sorted(
            tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints(name)
        )
        foreign_keys = sorted(
            (tuple(fk["constrained_columns"]), fk.get("referred_schema"),
             fk["referred_table"], tuple(fk["referred_columns"]),
             tuple(sorted(fk.get("options", {}).items())))
            for fk in inspector.get_foreign_keys(name)
        )
        result[name] = {
            "columns": columns,
            "primary_key": tuple(inspector.get_pk_constraint(name)["constrained_columns"]),
            "indexes": indexes,
            "unique": unique,
            "foreign_keys": foreign_keys,
            "checks": sorted(c["sqltext"] for c in inspector.get_check_constraints(name)),
        }
    return result


@lru_cache(maxsize=1)
def _known_schemas() -> tuple[dict, dict]:
    # Revision 0001 is immutable evidence of the original schema. Generate the
    # reference entirely in memory, never against the database being adopted.
    reference_engine = create_engine("sqlite://")
    migration_file = BACKEND_ROOT / "migrations/versions/0001_initial_schema.py"
    spec = importlib.util.spec_from_file_location("secops_legacy_schema", migration_file)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    try:
        with reference_engine.begin() as connection:
            with Operations.context(MigrationContext.configure(connection)):
                module.upgrade()
            initial_migration = _schema(connection)
    finally:
        reference_engine.dispose()

    # Original create_all used Python defaults and a unique key index rather
    # than the equivalent separate constraint used by revision 0001.
    original_orm = deepcopy(initial_migration)
    for table in original_orm.values():
        for name, column in table["columns"].items():
            table["columns"][name] = (*column[:3], None, *column[4:])
    original_orm["assets"]["unique"] = []
    original_orm["assets"]["indexes"] = [("ix_assets_key", ("key",), True, False)]
    return initial_migration, original_orm


def validate_legacy_schema(connection: Connection) -> None:
    actual = _schema(connection)
    candidates = _known_schemas()
    if actual not in candidates:
        differing = [
            name for name in sorted(LEGACY_TABLES)
            if all(actual[name] != candidate[name] for candidate in candidates)
        ]
        detail = ", ".join(differing) or "mixed schema variants"
        raise LegacySchemaError(f"Schema differs from supported revision 0001: {detail}")


def adopt_legacy_database(engine: Engine, *, backup_acknowledged: bool) -> None:
    if not backup_acknowledged:
        raise LegacySchemaError("A verified backup must be acknowledged before adoption")
    with engine.begin() as connection:
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN EXCLUSIVE")
        validate_legacy_schema(connection)
        if connection.dialect.name == "postgresql":
            connection.exec_driver_sql("SET LOCAL lock_timeout = '30s'")
            connection.exec_driver_sql(
                "LOCK TABLE assets, signals, findings, comments IN ACCESS EXCLUSIVE MODE"
            )
            validate_legacy_schema(connection)
        config = Config(str(BACKEND_ROOT / "alembic.ini"))
        config.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
        config.attributes["connection"] = connection
        command.stamp(config, "0001")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adopt", action="store_true", help="Stamp the verified schema at 0001")
    parser.add_argument("--acknowledge-backup", action="store_true",
                        help="Confirm a restorable backup exists and application writers are stopped")
    args = parser.parse_args(argv)
    if args.adopt and not args.acknowledge_backup:
        parser.error("--adopt requires --acknowledge-backup")

    from app.db import get_database_url
    url = get_database_url()
    if url.get_backend_name() == "sqlite" and (
        not url.database or url.database == ":memory:" or not Path(url.database).is_file()
    ):
        print("Legacy adoption refused: SQLite database file must already exist", file=sys.stderr)
        return 1
    engine = create_engine(url)
    try:
        if args.adopt:
            adopt_legacy_database(engine, backup_acknowledged=args.acknowledge_backup)
            print("Verified legacy schema stamped at 0001. Run alembic upgrade head separately.")
        else:
            with engine.connect() as connection:
                validate_legacy_schema(connection)
            print("Legacy schema verified. No changes made.")
    except LegacySchemaError as exc:
        print(f"Legacy adoption refused: {exc}", file=sys.stderr)
        return 1
    except Exception:
        # Database exceptions may contain connection details or data. Keep
        # operator output limited to the action, never a credential-bearing URL.
        print("Legacy adoption failed. Check database connectivity, permissions and schema; no upgrade was run.", file=sys.stderr)
        return 1
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
