"""CR-002 tests for CLEFIA-CTR-only credentials, decrypt-and-scan login, and Profile Note."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from scripts.demo_db_tools import reset_demo_database
from scripts.verify_postgres import verify_database_roundtrip
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from clefia.record_crypto import ClefiaKeyConfig, ClefiaRecordService
from web.auth import (
    PASSWORD_FIELD,
    PROFILE_NOTE_FIELD,
    USERNAME_FIELD,
    CorruptCredentialDataError,
    DemoCapacityExceededError,
    DuplicateUsernameError,
    InvalidCredentialsError,
    RateLimitExceededError,
    ValidationError,
    authenticate_user,
    canonicalize_username,
    change_user_password,
    check_and_increment_rate_limit,
    create_user_session,
    read_credentials_overview,
    read_profile_note_for_owner,
    register_user,
    reset_rate_limit,
    resolve_user_session,
    revoke_user_session,
    save_profile_note,
)
from web.config import Settings
from web.db import create_db_engine, create_session_factory
from web.models import AuthRateLimit, Base, EncryptedFieldRow, User, UserSession

_REPO_ROOT = Path(__file__).resolve().parent.parent
_ENC_HEX = "11" * 16
_SESSION_SECRET = "test-session-secret-with-diverse-characters-0123456789"


def _make_settings(db_url: str, *, demo_max_users: int = 100) -> Settings:
    crypto_cfg = ClefiaKeyConfig.from_hex(_ENC_HEX, "demo-v2")
    return Settings(
        database_url=db_url,
        crypto_config=crypto_cfg,
        session_secret_key=_SESSION_SECRET,
        app_env="test",
        secure_cookies=False,
        demo_max_users=demo_max_users,
    )


def _setup_sqlite_env(
    tmp_path: Path, name: str = "auth_v2.db"
) -> tuple[Path, Session, Settings]:
    db_file = tmp_path / name
    settings = _make_settings(f"sqlite+pysqlite:///{db_file.as_posix()}")
    engine = create_db_engine(settings.database_url)
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    return db_file, session_factory(), settings


def test_alembic_initial_schema_and_downgrade_upgrade_t006_t017(tmp_path: Path) -> None:
    """T-006/T-017: Single initial migration creates exact CR-002 tables and downgrades cleanly."""
    db_file = tmp_path / "alembic_clean.db"
    db_url = f"sqlite+pysqlite:///{db_file.as_posix()}"

    alembic_cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(_REPO_ROOT / "alembic"))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)

    command.upgrade(alembic_cfg, "head")
    engine = create_db_engine(db_url)
    inspector = inspect(engine)
    assert set(inspector.get_table_names()) == {
        "alembic_version",
        "users",
        "encrypted_fields",
        "user_sessions",
        "auth_rate_limits",
    }
    assert [c["name"] for c in inspector.get_columns("users")] == ["id", "created_at"]
    assert [c["name"] for c in inspector.get_columns("encrypted_fields")] == [
        "id",
        "owner_id",
        "field_name",
        "algorithm_version",
        "key_id",
        "nonce",
        "ciphertext",
        "updated_at",
    ]
    engine.dispose()

    command.downgrade(alembic_cfg, "base")
    engine_after_down = create_db_engine(db_url)
    assert set(inspect(engine_after_down).get_table_names()) == {"alembic_version"}
    engine_after_down.dispose()

    command.upgrade(alembic_cfg, "head")
    engine_after_reup = create_db_engine(db_url)
    settings = _make_settings(db_url)
    crypto = ClefiaRecordService(settings.crypto_config)
    with create_session_factory(engine_after_reup)() as db:
        new_user = register_user(db, crypto, username="clean_alice", password="CleanPass!1")
        auth = authenticate_user(db, crypto, username="clean_alice", password="CleanPass!1")
        assert auth.id == new_user.id
    engine_after_reup.dispose()


def test_t005_t006_registration_encrypts_credentials_with_no_plaintext(tmp_path: Path) -> None:
    """T-005/T-006: Registration stores distinct CTR nonces and zero plaintext in DB bytes."""
    db_file, db, settings = _setup_sqlite_env(tmp_path, "reg_v2.db")
    crypto = ClefiaRecordService(settings.crypto_config)
    raw_user = "  Alice_Demo.1  "
    raw_pw = "SimulasiPass!9876"

    try:
        alice = register_user(db, crypto, username=raw_user, password=raw_pw)
        assert alice.username == "alice_demo.1"

        rows = db.scalars(
            select(EncryptedFieldRow).where(EncryptedFieldRow.owner_id == alice.id)
        ).all()
        by_name = {r.field_name: r for r in rows}
        assert set(by_name.keys()) == {USERNAME_FIELD, PASSWORD_FIELD}

        u_row = by_name[USERNAME_FIELD]
        p_row = by_name[PASSWORD_FIELD]
        assert len(u_row.nonce) == 12
        assert len(p_row.nonce) == 12
        assert u_row.nonce != p_row.nonce
        assert u_row.ciphertext != b"alice_demo.1"
        assert p_row.ciphertext != raw_pw.encode("utf-8")

        overview = read_credentials_overview(db, crypto, owner_id=alice.id)
        assert overview.username == "alice_demo.1"
        assert overview.password_record.ciphertext_len_bytes == len(raw_pw.encode("utf-8"))
        assert overview.profile_note_record is None
    finally:
        db.close()

    raw_bytes = db_file.read_bytes()
    assert b"alice_demo.1" not in raw_bytes
    assert b"Alice_Demo.1" not in raw_bytes
    assert b"SimulasiPass!9876" not in raw_bytes
    assert b"argon2" not in raw_bytes.lower()


def test_registration_atomicity_and_demo_cap_t009(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Failed registration commits zero orphans and respects DEMO_MAX_USERS limit."""
    _, db, settings = _setup_sqlite_env(tmp_path, "atomic_v2.db")
    crypto = ClefiaRecordService(settings.crypto_config)

    def _boom() -> None:
        raise IntegrityError("INSERT INTO encrypted_fields", {}, Exception("forced"))

    try:
        monkeypatch.setattr(db, "commit", _boom)
        with pytest.raises(IntegrityError):
            register_user(db, crypto, username="atomic_user", password="AtomicPass!123")
        monkeypatch.undo()
        assert db.scalars(select(User)).all() == []
        assert db.scalars(select(EncryptedFieldRow)).all() == []

        register_user(db, crypto, username="cap_user_1", password="CapPassword!1", max_users=2)
        register_user(db, crypto, username="cap_user_2", password="CapPassword!2", max_users=2)
        with pytest.raises(DemoCapacityExceededError):
            register_user(
                db, crypto, username="cap_user_3", password="CapPassword!3", max_users=2
            )
    finally:
        db.close()


def test_concurrent_duplicate_registration_prevented_t009(tmp_path: Path) -> None:
    """T-009: Concurrent registration of the same canonical username allows only one."""
    db_file = tmp_path / "concurrent_reg.db"
    settings = _make_settings(f"sqlite+pysqlite:///{db_file.as_posix()}")
    engine = create_db_engine(settings.database_url)
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    crypto = ClefiaRecordService(settings.crypto_config)

    def _attempt(raw_name: str) -> str:
        with session_factory() as local_db:
            try:
                register_user(local_db, crypto, username=raw_name, password="ConcurrentPass!1")
                return "ok"
            except DuplicateUsernameError:
                return "dup"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_attempt, ["concurrent_alice", "  CONCURRENT_ALICE  "]))

    assert sorted(results) == ["dup", "ok"]
    with session_factory() as check_db:
        assert len(check_db.scalars(select(User)).all()) == 1
    engine.dispose()


def test_t008_unicode_nfkc_strip_casefold_canonicalization(tmp_path: Path) -> None:
    """T-008: NFKC + strip + casefold prevents duplicates and keeps passwords case-sensitive."""
    _, db, settings = _setup_sqlite_env(tmp_path, "nfkc_v2.db")
    crypto = ClefiaRecordService(settings.crypto_config)

    try:
        # Compatibility ligature \ufb01 ('fi') and NFC vs NFD accents must canonicalize identically
        assert canonicalize_username("\ufb01_User1") == "fi_user1"
        assert canonicalize_username("  FI_user1 ") == "fi_user1"
        assert canonicalize_username("Caf\u00e9_1") == canonicalize_username("CAFE\u0301_1")

        alice = register_user(db, crypto, username="\ufb01_User1", password="CaseSensitive!1")
        assert alice.username == "fi_user1"

        with pytest.raises(DuplicateUsernameError):
            register_user(db, crypto, username="  FI_user1 ", password="AnotherPass!2")

        auth = authenticate_user(db, crypto, username="  FI_user1 ", password="CaseSensitive!1")
        assert auth.id == alice.id

        # Password comparison must remain strictly case-sensitive
        with pytest.raises(InvalidCredentialsError):
            authenticate_user(db, crypto, username="fi_user1", password="casesensitive!1")

        for bad_user in ("ab", "   ", "ada spasi", "tanda@salah"):
            with pytest.raises(ValidationError):
                canonicalize_username(bad_user)
    finally:
        db.close()


def test_t007_approach_a_decrypt_and_scan_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-007: Login scans and decrypts usernames, then decrypts the matching password."""
    _, db, settings = _setup_sqlite_env(tmp_path, "scan_login.db")
    crypto = ClefiaRecordService(settings.crypto_config)

    try:
        register_user(db, crypto, username="pengguna_1", password="PassSatu!123")
        register_user(db, crypto, username="pengguna_2", password="PassDua!123")
        u3 = register_user(db, crypto, username="pengguna_3", password="PassTiga!123")

        decrypted_texts: list[str] = []
        orig_decrypt_text = crypto.decrypt_text

        def _spy_decrypt_text(encrypted):
            txt = orig_decrypt_text(encrypted)
            decrypted_texts.append(txt)
            return txt

        monkeypatch.setattr(crypto, "decrypt_text", _spy_decrypt_text)
        auth = authenticate_user(db, crypto, username="PENGGUNA_3", password="PassTiga!123")
        assert auth.id == u3.id
        # Approach A scans usernames 1, 2, 3 then decrypts matching password
        assert decrypted_texts == ["pengguna_1", "pengguna_2", "pengguna_3", "PassTiga!123"]
        monkeypatch.undo()

        # Unknown username & wrong password return generic InvalidCredentialsError
        with pytest.raises(InvalidCredentialsError, match="Nama pengguna atau kata sandi salah."):
            authenticate_user(db, crypto, username="tidak_ada", password="PassTiga!123")
        with pytest.raises(InvalidCredentialsError, match="Nama pengguna atau kata sandi salah."):
            authenticate_user(db, crypto, username="pengguna_3", password="SalahPassword!")

        # Corrupt UTF-8 on pengguna_1 must be skipped safely during scan so pengguna_3 still logs in
        u1_row = db.scalar(
            select(EncryptedFieldRow)
            .where(EncryptedFieldRow.field_name == USERNAME_FIELD)
            .order_by(EncryptedFieldRow.updated_at.asc(), EncryptedFieldRow.id.asc())
        )
        assert u1_row is not None
        u1_row.ciphertext = crypto.encrypt_bytes(b"\xff\xfe\xfd").ciphertext
        db.commit()
        assert (
            authenticate_user(db, crypto, username="pengguna_3", password="PassTiga!123").id
            == u3.id
        )
    finally:
        db.close()


def test_t010_change_password_rotates_nonce_and_revokes_other_sessions(tmp_path: Path) -> None:
    """T-010: Password change rotates nonce, rejects old password, and revokes peer sessions."""
    _, db, settings = _setup_sqlite_env(tmp_path, "pw_rotate_v2.db")
    crypto = ClefiaRecordService(settings.crypto_config)

    try:
        alice = register_user(db, crypto, username="ubah_alice", password="SandiLama!11")
        c1, s1 = create_user_session(db, user_id=alice.id, session_secret_key=_SESSION_SECRET)
        c2, _ = create_user_session(db, user_id=alice.id, session_secret_key=_SESSION_SECRET)

        pw_row = db.scalar(
            select(EncryptedFieldRow).where(
                EncryptedFieldRow.owner_id == alice.id,
                EncryptedFieldRow.field_name == PASSWORD_FIELD,
            )
        )
        assert pw_row is not None
        old_nonce = pw_row.nonce

        with pytest.raises(InvalidCredentialsError):
            change_user_password(
                db,
                crypto,
                owner_id=alice.id,
                current_password="SalahSandi!",
                new_password="SandiBaru!22",
                keep_session_id=s1.id,
            )

        with pytest.raises(ValidationError):
            change_user_password(
                db,
                crypto,
                owner_id=alice.id,
                current_password="SandiLama!11",
                new_password="SandiLama!11",
                keep_session_id=s1.id,
            )

        updated = change_user_password(
            db,
            crypto,
            owner_id=alice.id,
            current_password="SandiLama!11",
            new_password="SandiBaru!22",
            keep_session_id=s1.id,
        )
        assert updated.nonce != old_nonce
        assert (
            resolve_user_session(db, crypto, signed_cookie=c1, session_secret_key=_SESSION_SECRET)
            is not None
        )
        assert (
            resolve_user_session(db, crypto, signed_cookie=c2, session_secret_key=_SESSION_SECRET)
            is None
        )
        with pytest.raises(InvalidCredentialsError):
            authenticate_user(db, crypto, username="ubah_alice", password="SandiLama!11")
        assert (
            authenticate_user(db, crypto, username="ubah_alice", password="SandiBaru!22").id
            == alice.id
        )
    finally:
        db.close()


def test_t011_profile_note_preserved_isolation_and_bad_utf8_t012(tmp_path: Path) -> None:
    """T-011/T-012: Mandatory Profile Note handles UTF-8, owner isolation, and bad UTF-8 safely."""
    _, db, settings = _setup_sqlite_env(tmp_path, "profile_v2.db")
    crypto = ClefiaRecordService(settings.crypto_config)

    try:
        alice = register_user(db, crypto, username="catatan_alice", password="AlicePass!123")
        bob = register_user(db, crypto, username="catatan_bob", password="BobPass!456")

        long_note = "Catatan profil rahasia mahasiswa dengan teks Bahasa Indonesia > 16 byte!"
        saved1 = save_profile_note(db, crypto, owner_id=alice.id, note_text=long_note)
        assert saved1.field_name == PROFILE_NOTE_FIELD
        assert saved1.ciphertext != long_note.encode("utf-8")

        view = read_profile_note_for_owner(db, crypto, owner_id=alice.id)
        assert view is not None and view.plaintext_note == long_note
        assert read_profile_note_for_owner(db, crypto, owner_id=bob.id) is None

        # Empty note allowed cleanly; fresh nonce used on update
        saved_empty = save_profile_note(db, crypto, owner_id=alice.id, note_text="")
        assert saved_empty.nonce != saved1.nonce or saved_empty.ciphertext == b""
        view_empty = read_profile_note_for_owner(db, crypto, owner_id=alice.id)
        assert view_empty is not None and view_empty.plaintext_note == ""

        # Corrupt ciphertext decoding to invalid UTF-8 triggers safe CorruptCredentialDataError
        bad = crypto.encrypt_bytes(b"\xff\xfe\xfd")
        saved_empty.nonce = bad.nonce
        saved_empty.ciphertext = bad.ciphertext
        db.commit()
        with pytest.raises(CorruptCredentialDataError):
            read_profile_note_for_owner(db, crypto, owner_id=alice.id)
    finally:
        db.close()


def test_session_lifecycle_and_rate_limit_t013(tmp_path: Path) -> None:
    """Session cookie signature/expiry/revocation and DB rate limiter work properly."""
    _, db, settings = _setup_sqlite_env(tmp_path, "sess_rl_v2.db")
    crypto = ClefiaRecordService(settings.crypto_config)

    try:
        alice = register_user(db, crypto, username="sesi_alice", password="SessionPass!123")
        cookie, s_row = create_user_session(
            db, user_id=alice.id, session_secret_key=_SESSION_SECRET, ttl_seconds=60
        )
        res = resolve_user_session(
            db, crypto, signed_cookie=cookie, session_secret_key=_SESSION_SECRET
        )
        assert res is not None and res[0].username == "sesi_alice"
        assert (
            resolve_user_session(
                db, crypto, signed_cookie=cookie + "x", session_secret_key=_SESSION_SECRET
            )
            is None
        )

        s_row.expires_at = datetime.now(UTC) - timedelta(seconds=5)
        db.commit()
        assert (
            resolve_user_session(
                db, crypto, signed_cookie=cookie, session_secret_key=_SESSION_SECRET
            )
            is None
        )
        assert db.get(UserSession, s_row.id) is None

        c2, _ = create_user_session(db, user_id=alice.id, session_secret_key=_SESSION_SECRET)
        revoke_user_session(db, signed_cookie=c2, session_secret_key=_SESSION_SECRET)
        assert (
            resolve_user_session(
                db, crypto, signed_cookie=c2, session_secret_key=_SESSION_SECRET
            )
            is None
        )

        now = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
        bucket = "login:127.0.0.1"
        for i in range(3):
            check_and_increment_rate_limit(
                db, bucket_key=bucket, max_attempts=3, window_seconds=60, now=now
            )
            assert db.get(AuthRateLimit, bucket).attempt_count == i + 1
        with pytest.raises(RateLimitExceededError):
            check_and_increment_rate_limit(
                db, bucket_key=bucket, max_attempts=3, window_seconds=60, now=now
            )
        reset_rate_limit(db, bucket_key=bucket)
        assert db.get(AuthRateLimit, bucket) is None
    finally:
        db.close()


def test_verify_postgres_helper_and_demo_tools(tmp_path: Path) -> None:
    """verify_postgres helper and opt-in demo reset CLI work cleanly."""
    db_file = tmp_path / "helper_clean.db"
    settings = _make_settings(f"sqlite+pysqlite:///{db_file.as_posix()}")
    verify_database_roundtrip(settings)

    with pytest.raises(SystemExit):
        reset_demo_database(settings.database_url, confirm=False)

    engine = create_db_engine(settings.database_url)
    crypto = ClefiaRecordService(settings.crypto_config)
    with create_session_factory(engine)() as db:
        alice = register_user(db, crypto, username="reset_alice", password="ResetPass!1")
        save_profile_note(db, crypto, owner_id=alice.id, note_text="Catatan sementara")
        assert len(db.scalars(select(User)).all()) == 1
        assert len(db.scalars(select(EncryptedFieldRow)).all()) == 3
    engine.dispose()

    reset_demo_database(settings.database_url, confirm=True)
    engine_after = create_db_engine(settings.database_url)
    with create_session_factory(engine_after)() as db:
        assert db.scalars(select(User)).all() == []
        assert db.scalars(select(EncryptedFieldRow)).all() == []
    engine_after.dispose()
