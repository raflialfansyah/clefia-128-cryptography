"""SQLAlchemy engine and session management with bounded pooling for serverless safety."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool, StaticPool


def _enable_sqlite_foreign_keys(dbapi_connection: Any, connection_record: Any) -> None:
    _ = connection_record
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def create_db_engine(database_url: str, *, serverless: bool = False) -> Engine:
    """Create a SQLAlchemy Engine tuned for PostgreSQL (or SQLite in tests)."""
    if database_url.startswith("sqlite"):
        if ":memory:" in database_url:
            engine = create_engine(
                database_url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
        else:
            engine = create_engine(
                database_url,
                connect_args={"check_same_thread": False},
            )
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
        return engine

    if serverless:
        return create_engine(
            database_url,
            poolclass=NullPool,
            pool_pre_ping=True,
        )

    return create_engine(
        database_url,
        pool_size=5,
        max_overflow=2,
        pool_pre_ping=True,
        pool_recycle=300,
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Build a SQLAlchemy sessionmaker with expire_on_commit=False."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
