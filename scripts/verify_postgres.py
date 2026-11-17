"""Live PostgreSQL migration and CLEFIA-128-CTR verification script (T-017 helper).

Usage (with Docker Compose PostgreSQL or hosted PostgreSQL configured in environment/.env):
    uv run python scripts/verify_postgres.py

Verifies Alembic migration (`upgrade head`), `users` and `encrypted_fields`
schema structure, Approach A decrypt-and-scan registration/login, password
rotation with fresh nonces, mandatory Profile Note CRUD, cross-owner isolation,
and session revocation, then deletes its isolated test rows cleanly.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import delete, inspect, select, text

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from clefia.record_crypto import ClefiaRecordService  # noqa: E402
from web.auth import (  # noqa: E402
    PASSWORD_FIELD,
    PROFILE_NOTE_FIELD,
    USERNAME_FIELD,
    InvalidCredentialsError,
    authenticate_user,
    change_user_password,
    create_user_session,
    read_credentials_overview,
    read_profile_note_for_owner,
    register_user,
    resolve_user_session,
    revoke_user_session,
    save_profile_note,
)
from web.config import Settings  # noqa: E402
from web.db import create_db_engine, create_session_factory  # noqa: E402
from web.models import EncryptedFieldRow, User  # noqa: E402


def verify_database_roundtrip(settings: Settings, *, keep_rows: bool = False) -> None:
    """Run Alembic migration and end-to-end CR-002 DB CRUD verification."""
    alembic_cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(_REPO_ROOT / "alembic"))
    alembic_cfg.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(alembic_cfg, "head")

    engine = create_db_engine(settings.database_url, serverless=settings.serverless_db_pool)
    session_factory = create_session_factory(engine)
    crypto = ClefiaRecordService(settings.crypto_config)

    inspector = inspect(engine)
    assert inspector.has_table("users")
    assert inspector.has_table("encrypted_fields")
    user_cols = {col["name"] for col in inspector.get_columns("users")}
    assert user_cols == {"id", "created_at"}
    ef_cols = {col["name"] for col in inspector.get_columns("encrypted_fields")}
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

    suffix = uuid.uuid4().hex[:10]
    alice_name = f"pgcheck_alice_{suffix}"
    bob_name = f"pgcheck_bob_{suffix}"
    alice_pw_1 = "PgCheckAlicePass!1"
    alice_pw_2 = "PgCheckAlicePass!2"
    alice_secret = "Catatan verifikasi PostgreSQL - teks Bahasa Indonesia!"
    created_ids: list[uuid.UUID] = []

    try:
        with session_factory() as db:
            db.execute(text("SELECT 1"))

            alice = register_user(
                db,
                crypto,
                username=alice_name,
                password=alice_pw_1,
                max_users=settings.demo_max_users,
            )
            bob = register_user(
                db,
                crypto,
                username=bob_name,
                password="PgCheckBobPass!2",
                max_users=settings.demo_max_users,
            )
            created_ids.extend([alice.id, bob.id])

            auth_alice = authenticate_user(
                db,
                crypto,
                username=alice_name,
                password=alice_pw_1,
                max_users=settings.demo_max_users,
            )
            assert auth_alice.id == alice.id
            assert auth_alice.username == alice_name

            cred_rows = {
                row.field_name: row
                for row in db.scalars(
                    select(EncryptedFieldRow).where(EncryptedFieldRow.owner_id == alice.id)
                ).all()
            }
            assert USERNAME_FIELD in cred_rows and PASSWORD_FIELD in cred_rows
            assert cred_rows[USERNAME_FIELD].nonce != cred_rows[PASSWORD_FIELD].nonce
            assert cred_rows[USERNAME_FIELD].ciphertext != alice_name.encode("utf-8")
            assert cred_rows[PASSWORD_FIELD].ciphertext != alice_pw_1.encode("utf-8")

            overview = read_credentials_overview(db, crypto, owner_id=alice.id)
            assert overview.username == alice_name

            signed_cookie, session_row = create_user_session(
                db,
                user_id=alice.id,
                session_secret_key=settings.session_secret_key,
                ttl_seconds=settings.session_ttl_seconds,
            )
            resolved = resolve_user_session(
                db,
                crypto,
                signed_cookie=signed_cookie,
                session_secret_key=settings.session_secret_key,
                max_age_seconds=settings.session_ttl_seconds,
            )
            assert resolved is not None and resolved[0].id == alice.id
            assert resolved[1].id == session_row.id

            old_pw_nonce = cred_rows[PASSWORD_FIELD].nonce
            updated_pw = change_user_password(
                db,
                crypto,
                owner_id=alice.id,
                current_password=alice_pw_1,
                new_password=alice_pw_2,
                keep_session_id=session_row.id,
            )
            assert updated_pw.nonce != old_pw_nonce
            try:
                authenticate_user(
                    db,
                    crypto,
                    username=alice_name,
                    password=alice_pw_1,
                    max_users=settings.demo_max_users,
                )
                raise AssertionError("Old password must not authenticate after rotation")
            except InvalidCredentialsError:
                pass
            assert (
                authenticate_user(
                    db,
                    crypto,
                    username=alice_name,
                    password=alice_pw_2,
                    max_users=settings.demo_max_users,
                ).id
                == alice.id
            )

            saved = save_profile_note(db, crypto, owner_id=alice.id, note_text=alice_secret)
            assert saved.field_name == PROFILE_NOTE_FIELD
            assert saved.ciphertext != alice_secret.encode("utf-8")

            alice_view = read_profile_note_for_owner(db, crypto, owner_id=alice.id)
            assert alice_view is not None and alice_view.plaintext_note == alice_secret

            bob_view = read_profile_note_for_owner(db, crypto, owner_id=bob.id)
            assert bob_view is None, "Bob must not receive Alice's encrypted note"

            revoke_user_session(
                db,
                signed_cookie=signed_cookie,
                session_secret_key=settings.session_secret_key,
            )
            assert (
                resolve_user_session(
                    db,
                    crypto,
                    signed_cookie=signed_cookie,
                    session_secret_key=settings.session_secret_key,
                    max_age_seconds=settings.session_ttl_seconds,
                )
                is None
            )
    finally:
        if not keep_rows and created_ids:
            with session_factory() as db:
                db.execute(delete(User).where(User.id.in_(created_ids)))
                db.commit()
        engine.dispose()


def verify_postgres(*, keep_rows: bool = False) -> None:
    """Load settings from environment/.env, require PostgreSQL, and verify CRUD flow."""
    settings = Settings.from_env(load_env_file=True)
    if not settings.database_url.startswith("postgresql+psycopg://"):
        raise SystemExit(
            "verify_postgres.py requires a PostgreSQL DATABASE_URL (postgresql+psycopg://...)."
        )
    verify_database_roundtrip(settings, keep_rows=keep_rows)
    print("PostgreSQL Alembic upgrade + CR-002 CTR encrypted credentials/profile check passed.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify live PostgreSQL schema and CRUD flow.")
    parser.add_argument(
        "--keep-rows",
        action="store_true",
        help="Keep synthetic verification users instead of deleting them on exit.",
    )
    args = parser.parse_args()
    verify_postgres(keep_rows=args.keep_rows)


if __name__ == "__main__":
    main()
