"""Strict environment configuration and startup secret validation (CR-002 CLEFIA-only)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from clefia.record_crypto import ClefiaKeyConfig, KeyConfigurationError

_ALLOWED_ENVS = frozenset({"development", "test", "staging", "production"})
_MIN_SESSION_SECRET_LEN = 32
DEFAULT_DEMO_MAX_USERS = 100
_MAX_DEMO_USERS_LIMIT = 1000


class ConfigurationError(RuntimeError):
    """Raised when required configuration or cryptographic secrets fail validation."""


def _normalize_database_url(raw_url: str, app_env: str) -> str:
    """Validate and normalize DATABASE_URL to SQLAlchemy + psycopg dialect."""
    url = raw_url.strip()
    if not url:
        raise ConfigurationError("DATABASE_URL is required and cannot be empty")
    if "USER:PASSWORD@HOST" in url or "<" in url or ">" in url:
        raise ConfigurationError("DATABASE_URL contains an unreplaced placeholder value")

    if url.startswith("postgres://"):
        url = "postgresql+psycopg://" + url[len("postgres://") :]
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]

    is_postgres = url.startswith("postgresql+psycopg://")
    is_sqlite = url.startswith("sqlite+pysqlite://") or url.startswith("sqlite:///")

    if is_postgres:
        return url
    if is_sqlite and app_env == "test":
        return url
    if is_sqlite:
        raise ConfigurationError("SQLite DATABASE_URL is permitted only when APP_ENV=test")
    raise ConfigurationError(
        "DATABASE_URL must use postgresql+psycopg:// (or postgres:// / postgresql://)"
    )


def _validate_session_secret(raw_secret: str) -> str:
    """Validate SESSION_SECRET_KEY length and reject obvious placeholders."""
    secret = raw_secret.strip()
    if not secret:
        raise ConfigurationError("SESSION_SECRET_KEY is required")
    if "<" in secret or ">" in secret or "CHANGE_ME" in secret.upper():
        raise ConfigurationError("SESSION_SECRET_KEY contains a placeholder value")
    if len(secret) < _MIN_SESSION_SECRET_LEN:
        raise ConfigurationError(
            f"SESSION_SECRET_KEY must be at least {_MIN_SESSION_SECRET_LEN} characters"
        )
    if len(set(secret)) < 8:
        raise ConfigurationError("SESSION_SECRET_KEY has insufficient character diversity")
    return secret


def _parse_demo_max_users(raw_value: str) -> int:
    """Parse bounded demo user cap from DEMO_MAX_USERS."""
    cleaned = raw_value.strip()
    if not cleaned:
        return DEFAULT_DEMO_MAX_USERS
    try:
        parsed = int(cleaned)
    except ValueError as exc:
        raise ConfigurationError("DEMO_MAX_USERS must be an integer") from exc
    if parsed < 1 or parsed > _MAX_DEMO_USERS_LIMIT:
        raise ConfigurationError(
            f"DEMO_MAX_USERS must be between 1 and {_MAX_DEMO_USERS_LIMIT}"
        )
    return parsed


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated runtime settings for the Indonesian CLEFIA-128 academic web demonstrator."""

    database_url: str
    crypto_config: ClefiaKeyConfig
    session_secret_key: str
    app_env: str
    secure_cookies: bool
    serverless_db_pool: bool = False
    demo_max_users: int = DEFAULT_DEMO_MAX_USERS
    session_ttl_seconds: int = 3600
    rate_limit_max_attempts: int = 5
    rate_limit_window_seconds: int = 300

    @classmethod
    def from_env(cls, *, load_env_file: bool = True) -> Settings:
        """Load and strictly validate runtime settings from environment variables."""
        if load_env_file:
            env_path = Path.cwd() / ".env"
            if env_path.is_file():
                load_dotenv(dotenv_path=env_path, override=False)

        app_env = os.environ.get("APP_ENV", "development").strip().lower()
        if app_env not in _ALLOWED_ENVS:
            raise ConfigurationError(
                f"APP_ENV must be one of {sorted(_ALLOWED_ENVS)}, got {app_env!r}"
            )

        database_url = _normalize_database_url(os.environ.get("DATABASE_URL", ""), app_env)

        enc_hex = os.environ.get("CLEFIA_ENC_KEY_HEX", "").strip()
        key_id = os.environ.get("CLEFIA_KEY_ID", "").strip()
        if "<" in enc_hex or ">" in enc_hex:
            raise ConfigurationError("CLEFIA_ENC_KEY_HEX contains a placeholder value")
        if "<" in key_id or ">" in key_id:
            raise ConfigurationError("CLEFIA_KEY_ID contains a placeholder value")
        try:
            crypto_config = ClefiaKeyConfig.from_hex(enc_hex, key_id)
        except KeyConfigurationError as exc:
            raise ConfigurationError(str(exc)) from exc

        session_secret_key = _validate_session_secret(os.environ.get("SESSION_SECRET_KEY", ""))
        demo_max_users = _parse_demo_max_users(os.environ.get("DEMO_MAX_USERS", ""))

        secure_env = os.environ.get("SESSION_COOKIE_SECURE", "").strip().lower()
        if secure_env in {"1", "true", "yes"}:
            secure_cookies = True
        elif secure_env in {"0", "false", "no"} and app_env != "production":
            secure_cookies = False
        else:
            secure_cookies = app_env in {"production", "staging"}

        serverless_pool = bool(
            os.environ.get("VERCEL")
            or os.environ.get("DB_SERVERLESS_POOL", "").strip().lower() in {"1", "true", "yes"}
        )

        return cls(
            database_url=database_url,
            crypto_config=crypto_config,
            session_secret_key=session_secret_key,
            app_env=app_env,
            secure_cookies=secure_cookies,
            serverless_db_pool=serverless_pool,
            demo_max_users=demo_max_users,
        )
