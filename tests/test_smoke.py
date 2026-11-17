"""Smoke and CR-002 hygiene tests for package separation, startup guards, and legacy removal."""

from __future__ import annotations

import ast
import importlib
import importlib.util
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from web import create_app
from web.config import ConfigurationError, Settings
from web.models import EncryptedFieldRow, User

_REPO_ROOT = Path(__file__).resolve().parent.parent


def test_clefia_package_is_independent_of_web_stack() -> None:
    """Core clefia package must import without FastAPI, SQLAlchemy, HMAC, or Argon2."""
    import clefia

    assert hasattr(clefia, "encrypt_block")
    assert hasattr(clefia, "decrypt_block")
    assert hasattr(clefia, "ClefiaRecordService")

    package_dir = Path(clefia.__file__).resolve().parent
    forbidden = ("fastapi", "sqlalchemy", "alembic", "uvicorn", "jinja2", "argon" + "2", "hmac")
    for py_file in package_dir.glob("*.py"):
        text = py_file.read_text(encoding="utf-8").lower()
        for word in forbidden:
            assert word not in text, f"Core module {py_file.name} references '{word}'"


def test_app_entrypoint_exports_fastapi_instance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ASGI app module exports a runnable FastAPI instance when secrets are configured."""
    db_file = tmp_path / "asgi_entrypoint.db"
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("CLEFIA_ENC_KEY_HEX", "11" * 16)
    monkeypatch.setenv("CLEFIA_KEY_ID", "smoke-v2")
    monkeypatch.setenv("SESSION_SECRET_KEY", "smoke-session-secret-0123456789abcdef")

    import app as asgi_app

    importlib.reload(asgi_app)
    assert isinstance(asgi_app.app, FastAPI)


def test_health_endpoint_returns_ok(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Configured app responds healthy on GET /health and checks DB connectivity."""
    db_file = tmp_path / "smoke_health.db"
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("CLEFIA_ENC_KEY_HEX", "11" * 16)
    monkeypatch.setenv("CLEFIA_KEY_ID", "smoke-v2")
    monkeypatch.setenv("SESSION_SECRET_KEY", "smoke-session-secret-0123456789abcdef")

    test_app = create_app(Settings.from_env(load_env_file=False))
    with TestClient(test_app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "service": "clefia128-capstone"}


def test_startup_fails_closed_when_secrets_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """App initialization fails closed on missing, placeholder, or invalid config."""
    for env_name in (
        "DATABASE_URL",
        "CLEFIA_ENC_KEY_HEX",
        "CLEFIA_KEY_ID",
        "SESSION_SECRET_KEY",
        "DEMO_MAX_USERS",
    ):
        monkeypatch.delenv(env_name, raising=False)

    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    with pytest.raises(ConfigurationError), TestClient(create_app()):
        pass

    # Invalid key length fails closed
    monkeypatch.setenv("CLEFIA_ENC_KEY_HEX", "11" * 15)
    monkeypatch.setenv("CLEFIA_KEY_ID", "smoke-v2")
    monkeypatch.setenv("SESSION_SECRET_KEY", "smoke-session-secret-0123456789abcdef")
    with pytest.raises(ConfigurationError):
        Settings.from_env(load_env_file=False)

    # SQLite disallowed outside APP_ENV=test
    monkeypatch.setenv("CLEFIA_ENC_KEY_HEX", "11" * 16)
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(ConfigurationError):
        Settings.from_env(load_env_file=False)

    # Out-of-range DEMO_MAX_USERS rejected
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DEMO_MAX_USERS", "0")
    with pytest.raises(ConfigurationError):
        Settings.from_env(load_env_file=False)


def test_no_legacy_hmac_blind_index_or_argon2_in_active_app_t019() -> None:
    """T-019: Active app/core/env must contain zero HMAC, blind-index, or Argon2 code."""
    argon_word = "argon" + "2"
    assert importlib.util.find_spec(argon_word) is None

    legacy_terms = (
        argon_word,
        "username" + "_lookup",
        "password" + "_hash",
        "auth" + "_tag",
        "user_encrypted" + "_fields",
        "profile_encrypted" + "_fields",
        "CLEFIA_MAC_" + "KEY_HEX",
        "USERNAME_INDEX_" + "KEY_HEX",
    )

    for manifest_name in ("pyproject.toml", "uv.lock", ".env.example"):
        content = (_REPO_ROOT / manifest_name).read_text(encoding="utf-8")
        lowered = content.lower()
        for term in legacy_terms:
            assert term.lower() not in lowered, f"{manifest_name} still references {term}"

    # Verify zero active HMAC/Argon2 imports or obsolete identifiers across code, scripts, alembic
    forbidden_modules = {"hmac", argon_word, "argon2_cffi"}
    for folder in ("src", "experiments", "scripts", "alembic"):
        for file_path in (_REPO_ROOT / folder).rglob("*"):
            if file_path.is_file() and file_path.suffix == ".py":
                source = file_path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(file_path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            top = alias.name.split(".")[0].lower()
                            assert top not in forbidden_modules, (
                                f"{file_path} imports forbidden module {alias.name}"
                            )
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        top = node.module.split(".")[0].lower()
                        assert top not in forbidden_modules, (
                            f"{file_path} imports from forbidden module {node.module}"
                        )
                lowered = source.lower()
                for term in legacy_terms:
                    assert term.lower() not in lowered, (
                        f"{file_path} still references {term}"
                    )

    version_files = sorted(
        p.name for p in (_REPO_ROOT / "alembic" / "versions").glob("*.py")
    )
    assert version_files == ["0001_initial_schema.py"]

    # Active HTML may explain why HMAC is removed ("tanpa MAC/HMAC"), so only check columns/keys
    assert list(User.__table__.columns.keys()) == ["id", "created_at"]
    ef_cols = set(EncryptedFieldRow.__table__.columns.keys())
    assert ("auth" + "_tag") not in ef_cols
    assert ef_cols == {
        "id",
        "owner_id",
        "field_name",
        "algorithm_version",
        "key_id",
        "nonce",
        "ciphertext",
        "updated_at",
    }
