"""SQLAlchemy 2.x ORM models for CR-002 CLEFIA-CTR-only persistence."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class User(Base):
    """Registered synthetic account with zero plaintext credentials or blind index."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    encrypted_fields: Mapped[list[EncryptedFieldRow]] = relationship(
        back_populates="owner",
        cascade="all, delete-orphan",
    )
    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )


class EncryptedFieldRow(Base):
    """CLEFIA-128-CTR encrypted field stored without MAC authentication tags.

    Used for 'username', 'password', and mandatory 'profile_note'.
    """

    __tablename__ = "encrypted_fields"
    __table_args__ = (
        UniqueConstraint("owner_id", "field_name", name="uq_encrypted_fields_owner_field"),
        UniqueConstraint("key_id", "nonce", name="uq_encrypted_fields_key_nonce"),
        Index("ix_encrypted_fields_owner_field", "owner_id", "field_name"),
        Index("ix_encrypted_fields_field_owner", "field_name", "owner_id"),
        CheckConstraint(
            "field_name IN ('username', 'password', 'profile_note')",
            name="ck_encrypted_fields_field_name",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    field_name: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    owner: Mapped[User] = relationship(back_populates="encrypted_fields")


class UserSession(Base):
    """Server-managed revocable authentication session with per-session CSRF token."""

    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped[User] = relationship(back_populates="sessions")


class AuthRateLimit(Base):
    """Durable fixed-window rate-limiting bucket for auth endpoints."""

    __tablename__ = "auth_rate_limits"

    bucket_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window_started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
