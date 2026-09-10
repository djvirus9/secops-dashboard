from logging.config import fileConfig
import os

from sqlalchemy import engine_from_config, pool
from alembic import context
from app.db import get_database_url

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Override sqlalchemy.url from environment if set
if os.environ.get("DATABASE_URL") or os.environ.get("PGHOST"):
    db_url = get_database_url().render_as_string(hide_password=False)
    # Alembic's ConfigParser performs interpolation; a valid URL can contain
    # percent-encoded passwords such as %40. Escape only for this config layer.
    config.set_main_option("sqlalchemy.url", db_url.replace("%", "%%"))

from app.models import Base  # noqa: E402 — must be after path setup
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    supplied_connection = config.attributes.get("connection")
    if supplied_connection is not None:
        context.configure(connection=supplied_connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
        return
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
