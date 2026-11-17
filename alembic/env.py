"""Alembic migration environment configured for PostgreSQL and test SQLite databases."""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import engine_from_config, pool

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from web.models import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _resolve_database_url() -> str:
    """Resolve database URL from Alembic -x, sqlalchemy.url, or DATABASE_URL env."""
    x_args = context.get_x_argument(as_dictionary=True)
    if x_args.get("db_url"):
        return str(x_args["db_url"])

    configured = config.get_main_option("sqlalchemy.url")
    if configured:
        return configured

    env_path = _ROOT / ".env"
    if env_path.is_file():
        load_dotenv(dotenv_path=env_path, override=False)

    env_url = os.environ.get("DATABASE_URL", "").strip()
    if env_url.startswith("postgres://"):
        return "postgresql+psycopg://" + env_url[len("postgres://") :]
    if env_url.startswith("postgresql://"):
        return "postgresql+psycopg://" + env_url[len("postgresql://") :]
    if env_url:
        return env_url

    if context.is_offline_mode():
        # Allow `alembic upgrade head --sql` to emit PostgreSQL DDL without secrets
        return "postgresql+psycopg://localhost/clefia"

    raise RuntimeError("DATABASE_URL must be configured to run online Alembic migrations")


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (SQL DDL generation)."""
    url = _resolve_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _resolve_database_url()
    connectable = engine_from_config(
        section,
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
