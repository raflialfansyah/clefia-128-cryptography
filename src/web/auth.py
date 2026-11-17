"""CLEFIA-CTR-only credential storage, decrypt-and-scan lookup, sessions, and Profile Note.

CR-002 academic-only demonstrator rules:
    - Both synthetic username and password (plus mandatory profile_note) are encrypted
      using CLEFIA-128-CTR via ClefiaRecordService without HMAC authentication tags.
    - Account uniqueness check and login use Approach A (bounded O(n) decrypt-and-scan
      over stored encrypted 'username' rows), with zero blind index or password hashing.
    - All user-visible validation and error strings use Bahasa Indonesia.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import threading
import unicodedata
import uuid
from contextlib import AbstractContextManager, nullcontext
from datetime import UTC, datetime, timedelta

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from clefia.record_crypto import ClefiaRecordService, EncryptedField, RecordCryptoError
from web.models import AuthRateLimit, EncryptedFieldRow, User, UserSession
from web.schemas import (
    AuthenticatedUser,
    CredentialsOverviewView,
    EncryptedFieldMetadataView,
    ProfileNoteView,
)

logger = logging.getLogger(__name__)

USERNAME_FIELD = "username"
PASSWORD_FIELD = "password"
PROFILE_NOTE_FIELD = "profile_note"

_USERNAME_MIN_CHARS = 3
_USERNAME_MAX_CHARS = 64
_USERNAME_MAX_BYTES = 128
_PASSWORD_MIN_LEN = 8
_PASSWORD_MAX_LEN = 128
_PROFILE_NOTE_MAX_CHARS = 4096
_SESSION_SALT = "clefia128-session-cookie-v2"
_PREAUTH_CSRF_SALT = "clefia128-preauth-csrf-v2"
_MAX_NONCE_RETRIES = 5
_PG_REGISTRATION_LOCK_ID = 1129071942  # Deterministic int32 advisory lock key ('CLEF')
_SQLITE_REG_LOCK = threading.Lock()


class AuthError(Exception):
    """Base exception for authentication and credential errors."""


class ValidationError(AuthError):
    """Raised when username, password, or profile note input fails validation."""


class DuplicateUsernameError(AuthError):
    """Raised when registering a canonical username that already exists."""


class DemoCapacityExceededError(AuthError):
    """Raised when the synthetic demo account limit (DEMO_MAX_USERS) has been reached."""


class InvalidCredentialsError(AuthError):
    """Raised when login credentials or current password verification fails."""


class RateLimitExceededError(AuthError):
    """Raised when an auth bucket exceeds allowed attempts within the window."""


class SessionNotFoundError(AuthError):
    """Raised when no valid active session or user account exists."""


class CorruptCredentialDataError(AuthError):
    """Raised when a stored encrypted field cannot be structurally decoded as UTF-8."""


def canonicalize_username(raw_username: str) -> str:
    """Normalize synthetic demo username: Unicode NFKC -> strip() -> casefold()."""
    if not isinstance(raw_username, str):
        raise ValidationError("Nama pengguna harus berupa teks.")
    cleaned = unicodedata.normalize("NFKC", raw_username).strip().casefold().strip()
    if len(cleaned) < _USERNAME_MIN_CHARS or len(cleaned) > _USERNAME_MAX_CHARS:
        raise ValidationError(
            f"Nama pengguna harus terdiri dari {_USERNAME_MIN_CHARS} hingga "
            f"{_USERNAME_MAX_CHARS} karakter."
        )
    if len(cleaned.encode("utf-8")) > _USERNAME_MAX_BYTES:
        raise ValidationError(
            f"Nama pengguna maksimal {_USERNAME_MAX_BYTES} byte UTF-8."
        )
    if any(not (ch.isalnum() or ch in {"_", ".", "-"}) for ch in cleaned):
        raise ValidationError(
            "Nama pengguna hanya boleh berisi huruf, angka, '.', '_', atau '-' tanpa spasi."
        )
    return cleaned


def validate_password(raw_password: str) -> str:
    """Validate synthetic password length constraints without normalizing characters."""
    if not isinstance(raw_password, str):
        raise ValidationError("Kata sandi harus berupa teks.")
    if len(raw_password) < _PASSWORD_MIN_LEN:
        raise ValidationError(
            f"Kata sandi minimal terdiri dari {_PASSWORD_MIN_LEN} karakter."
        )
    if len(raw_password) > _PASSWORD_MAX_LEN or len(raw_password.encode("utf-8")) > 512:
        raise ValidationError(
            f"Kata sandi maksimal {_PASSWORD_MAX_LEN} karakter."
        )
    return raw_password


def _ensure_utc(dt: datetime) -> datetime:
    """Normalize naive datetimes (e.g. from SQLite) to UTC-aware datetimes."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _row_to_encrypted_field(row: EncryptedFieldRow) -> EncryptedField:
    return EncryptedField(
        version=row.algorithm_version,
        key_id=row.key_id,
        nonce=row.nonce,
        ciphertext=row.ciphertext,
    )


def _row_to_metadata_view(row: EncryptedFieldRow) -> EncryptedFieldMetadataView:
    return EncryptedFieldMetadataView(
        field_name=row.field_name,
        algorithm="CLEFIA-128",
        mode="CTR",
        key_id=row.key_id,
        algorithm_version=row.algorithm_version,
        nonce_hex=row.nonce.hex(),
        ciphertext_hex=row.ciphertext.hex(),
        ciphertext_b64=base64.b64encode(row.ciphertext).decode("ascii"),
        ciphertext_len_bytes=len(row.ciphertext),
        updated_at=_ensure_utc(row.updated_at),
    )


def _make_encrypted_row(
    *,
    owner_id: uuid.UUID,
    field_name: str,
    encrypted: EncryptedField,
    now: datetime,
) -> EncryptedFieldRow:
    return EncryptedFieldRow(
        owner_id=owner_id,
        field_name=field_name,
        algorithm_version=encrypted.version,
        key_id=encrypted.key_id,
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext,
        updated_at=now,
    )


def _registration_critical_section(db: Session) -> AbstractContextManager[None]:
    """Serialize registration check-and-insert across workers or threads."""
    bind = db.get_bind()
    dialect = bind.dialect.name if bind is not None else ""
    if dialect == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": _PG_REGISTRATION_LOCK_ID},
        )
        return nullcontext()
    return _SQLITE_REG_LOCK


def _upsert_encrypted_field(
    db: Session,
    crypto: ClefiaRecordService,
    *,
    owner_id: uuid.UUID,
    field_name: str,
    plaintext: str,
    allow_empty: bool = True,
    avoid_nonce: bytes | None = None,
) -> EncryptedFieldRow:
    """Encrypt text via CLEFIA-128-CTR and upsert row with nonce-collision retry."""
    for _ in range(_MAX_NONCE_RETRIES):
        encrypted = crypto.encrypt_text(
            plaintext,
            key_id=crypto.key_id,
            allow_empty=allow_empty,
        )
        if avoid_nonce is not None and encrypted.nonce == avoid_nonce:
            continue

        existing = db.scalar(
            select(EncryptedFieldRow).where(
                EncryptedFieldRow.owner_id == owner_id,
                EncryptedFieldRow.field_name == field_name,
            )
        )
        now = datetime.now(UTC)
        if existing is None:
            record = _make_encrypted_row(
                owner_id=owner_id,
                field_name=field_name,
                encrypted=encrypted,
                now=now,
            )
            db.add(record)
        else:
            existing.algorithm_version = encrypted.version
            existing.key_id = encrypted.key_id
            existing.nonce = encrypted.nonce
            existing.ciphertext = encrypted.ciphertext
            existing.updated_at = now
            record = existing

        try:
            db.commit()
            db.refresh(record)
            return record
        except IntegrityError as exc:
            db.rollback()
            err_msg = str(exc).lower()
            if "nonce" in err_msg or "uq_encrypted_fields_key_nonce" in err_msg:
                continue
            raise

    raise RuntimeError("Batas percobaan ulang keunikan nonce terlampaui.")


def check_and_increment_rate_limit(
    db: Session,
    *,
    bucket_key: str,
    max_attempts: int,
    window_seconds: int,
    now: datetime | None = None,
) -> None:
    """Enforce a fixed-window DB-backed rate limit for auth routes."""
    current_time = now or datetime.now(UTC)
    bucket = db.get(AuthRateLimit, bucket_key)
    if bucket is None:
        db.add(
            AuthRateLimit(
                bucket_key=bucket_key,
                attempt_count=1,
                window_started_at=current_time,
            )
        )
        db.commit()
        return

    window_start = _ensure_utc(bucket.window_started_at)
    if (current_time - window_start).total_seconds() >= window_seconds:
        bucket.attempt_count = 1
        bucket.window_started_at = current_time
        db.commit()
        return

    if bucket.attempt_count >= max_attempts:
        raise RateLimitExceededError("Terlalu banyak percobaan. Coba lagi nanti.")

    bucket.attempt_count += 1
    db.commit()


def reset_rate_limit(db: Session, *, bucket_key: str) -> None:
    """Clear rate-limit bucket after a successful authentication."""
    db.execute(delete(AuthRateLimit).where(AuthRateLimit.bucket_key == bucket_key))
    db.commit()


def _scan_encrypted_usernames(
    db: Session,
    crypto: ClefiaRecordService,
    *,
    canonical_target: str,
    scan_limit: int,
) -> EncryptedFieldRow | None:
    """Approach A: decrypt stored encrypted usernames sequentially until matched."""
    rows = db.scalars(
        select(EncryptedFieldRow)
        .where(EncryptedFieldRow.field_name == USERNAME_FIELD)
        .order_by(EncryptedFieldRow.updated_at.asc(), EncryptedFieldRow.id.asc())
        .limit(scan_limit)
    ).all()

    target_bytes = canonical_target.encode("utf-8")
    for row in rows:
        try:
            stored_name = crypto.decrypt_text(_row_to_encrypted_field(row))
        except RecordCryptoError:
            logger.warning("Skipping unreadable username record_id=%s", row.id)
            continue
        if secrets.compare_digest(stored_name.encode("utf-8"), target_bytes):
            return row
    return None


def register_user(
    db: Session,
    crypto: ClefiaRecordService,
    *,
    username: str,
    password: str,
    max_users: int = 100,
) -> AuthenticatedUser:
    """Register a synthetic user atomically after bounded decrypt-and-scan duplicate check."""
    canonical = canonicalize_username(username)
    validated_password = validate_password(password)

    with _registration_critical_section(db):
        existing_count = db.scalar(select(func.count(User.id))) or 0
        if existing_count >= max_users:
            raise DemoCapacityExceededError(
                f"Batas kapasitas akun simulasi demo ({max_users} akun) telah tercapai."
            )

        duplicate_row = _scan_encrypted_usernames(
            db,
            crypto,
            canonical_target=canonical,
            scan_limit=max_users + 1,
        )
        if duplicate_row is not None:
            raise DuplicateUsernameError("Nama pengguna sudah digunakan.")

        user_id = uuid.uuid4()
        for _ in range(_MAX_NONCE_RETRIES):
            u_enc = crypto.encrypt_text(canonical, key_id=crypto.key_id, allow_empty=False)
            p_enc = crypto.encrypt_text(
                validated_password,
                key_id=crypto.key_id,
                allow_empty=False,
            )
            if u_enc.nonce == p_enc.nonce:
                continue

            now = datetime.now(UTC)
            user_row = User(id=user_id, created_at=now)
            u_row = _make_encrypted_row(
                owner_id=user_id,
                field_name=USERNAME_FIELD,
                encrypted=u_enc,
                now=now,
            )
            p_row = _make_encrypted_row(
                owner_id=user_id,
                field_name=PASSWORD_FIELD,
                encrypted=p_enc,
                now=now,
            )
            db.add_all([user_row, u_row, p_row])
            try:
                db.commit()
                return AuthenticatedUser(id=user_id, username=canonical, created_at=now)
            except IntegrityError as exc:
                db.rollback()
                err_msg = str(exc).lower()
                if "nonce" in err_msg or "uq_encrypted_fields_key_nonce" in err_msg:
                    continue
                raise

    raise RuntimeError("Batas percobaan ulang keunikan nonce saat pendaftaran terlampaui.")


def authenticate_user(
    db: Session,
    crypto: ClefiaRecordService,
    *,
    username: str,
    password: str,
    max_users: int = 100,
) -> AuthenticatedUser:
    """Approach A login: decrypt usernames linearly, then decrypt & compare password."""
    if not isinstance(password, str) or not password:
        raise InvalidCredentialsError("Nama pengguna atau kata sandi salah.")

    try:
        canonical = canonicalize_username(username)
    except ValidationError as exc:
        raise InvalidCredentialsError("Nama pengguna atau kata sandi salah.") from exc

    matched_user_row = _scan_encrypted_usernames(
        db,
        crypto,
        canonical_target=canonical,
        scan_limit=max_users + 1,
    )
    if matched_user_row is None:
        raise InvalidCredentialsError("Nama pengguna atau kata sandi salah.")

    password_row = db.scalar(
        select(EncryptedFieldRow).where(
            EncryptedFieldRow.owner_id == matched_user_row.owner_id,
            EncryptedFieldRow.field_name == PASSWORD_FIELD,
        )
    )
    if password_row is None:
        logger.warning("Missing password record for user record_id=%s", matched_user_row.id)
        raise InvalidCredentialsError("Nama pengguna atau kata sandi salah.")

    try:
        stored_password = crypto.decrypt_text(_row_to_encrypted_field(password_row))
    except RecordCryptoError as exc:
        logger.warning("Unreadable password record_id=%s", password_row.id)
        raise InvalidCredentialsError("Nama pengguna atau kata sandi salah.") from exc

    pw_match = secrets.compare_digest(
        stored_password.encode("utf-8"),
        password.encode("utf-8"),
    )
    del stored_password
    if not pw_match:
        raise InvalidCredentialsError("Nama pengguna atau kata sandi salah.")

    user = db.get(User, matched_user_row.owner_id)
    if user is None:
        raise InvalidCredentialsError("Nama pengguna atau kata sandi salah.")

    return AuthenticatedUser(
        id=user.id,
        username=canonical,
        created_at=_ensure_utc(user.created_at),
    )


def _hash_session_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt=_SESSION_SALT)


def _preauth_csrf_serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt=_PREAUTH_CSRF_SALT)


def issue_preauth_csrf_pair(
    secret_key: str,
    existing_cookie: str | None = None,
    *,
    max_age_seconds: int = 3600,
) -> tuple[str, str, bool]:
    """Return `(raw_token, signed_cookie, should_set_cookie)` for public POST forms."""
    ser = _preauth_csrf_serializer(secret_key)
    if existing_cookie:
        try:
            payload = ser.loads(existing_cookie, max_age=max_age_seconds)
            if isinstance(payload, dict) and isinstance(payload.get("c"), str) and payload["c"]:
                return payload["c"], existing_cookie, False
        except (BadSignature, SignatureExpired):
            pass

    raw_token = secrets.token_urlsafe(24)
    signed_cookie = ser.dumps({"c": raw_token})
    return raw_token, signed_cookie, True


def verify_preauth_csrf(
    secret_key: str,
    cookie_value: str | None,
    submitted_token: str | None,
    *,
    max_age_seconds: int = 3600,
) -> bool:
    """Verify public-form pre-auth double-submit CSRF token in constant time."""
    if not cookie_value or not isinstance(submitted_token, str) or not submitted_token:
        return False
    ser = _preauth_csrf_serializer(secret_key)
    try:
        payload = ser.loads(cookie_value, max_age=max_age_seconds)
    except (BadSignature, SignatureExpired):
        return False
    expected = payload.get("c") if isinstance(payload, dict) else None
    if not isinstance(expected, str) or not expected:
        return False
    return secrets.compare_digest(expected, submitted_token)


def create_user_session(
    db: Session,
    *,
    user_id: uuid.UUID,
    session_secret_key: str,
    ttl_seconds: int = 3600,
) -> tuple[str, UserSession]:
    """Create a fresh revocable DB session (renewed at login) and return signed cookie."""
    raw_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    session_row = UserSession(
        user_id=user_id,
        token_hash=_hash_session_token(raw_token),
        csrf_token=csrf_token,
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
    )
    db.add(session_row)
    db.commit()
    db.refresh(session_row)

    signed_cookie = _serializer(session_secret_key).dumps({"t": raw_token})
    return signed_cookie, session_row


def resolve_user_session(
    db: Session,
    crypto: ClefiaRecordService,
    *,
    signed_cookie: str | None,
    session_secret_key: str,
    max_age_seconds: int = 3600,
) -> tuple[AuthenticatedUser, UserSession] | None:
    """Validate signed session cookie and hydrate authenticated owner via CLEFIA username."""
    if not signed_cookie:
        return None
    try:
        payload = _serializer(session_secret_key).loads(signed_cookie, max_age=max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("t"), str):
        return None

    token_hash = _hash_session_token(payload["t"])
    session_row = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash))
    if session_row is None:
        return None

    now = datetime.now(UTC)
    if _ensure_utc(session_row.expires_at) <= now:
        db.delete(session_row)
        db.commit()
        return None

    user = db.get(User, session_row.user_id)
    if user is None:
        return None

    username_row = db.scalar(
        select(EncryptedFieldRow).where(
            EncryptedFieldRow.owner_id == user.id,
            EncryptedFieldRow.field_name == USERNAME_FIELD,
        )
    )
    if username_row is None:
        return None

    try:
        username_str = crypto.decrypt_text(_row_to_encrypted_field(username_row))
    except RecordCryptoError:
        logger.warning("Failed to decode session username record_id=%s", username_row.id)
        return None

    auth_user = AuthenticatedUser(
        id=user.id,
        username=username_str,
        created_at=_ensure_utc(user.created_at),
    )
    return auth_user, session_row


def revoke_user_session(
    db: Session,
    *,
    signed_cookie: str | None,
    session_secret_key: str,
) -> None:
    """Revoke active session from DB on explicit logout."""
    if not signed_cookie:
        return
    try:
        payload = _serializer(session_secret_key).loads(signed_cookie)
    except BadSignature:
        return
    if not isinstance(payload, dict) or not isinstance(payload.get("t"), str):
        return
    token_hash = _hash_session_token(payload["t"])
    db.execute(delete(UserSession).where(UserSession.token_hash == token_hash))
    db.commit()


def verify_csrf_token(session_row: UserSession, submitted_token: str | None) -> bool:
    """Verify per-session CSRF token in constant time."""
    if not isinstance(submitted_token, str) or not submitted_token:
        return False
    return secrets.compare_digest(session_row.csrf_token, submitted_token)


def read_credentials_overview(
    db: Session,
    crypto: ClefiaRecordService,
    *,
    owner_id: uuid.UUID,
) -> CredentialsOverviewView:
    """Return owner's CLEFIA-128-CTR ciphertext/nonce metadata (never password plaintext)."""
    user = db.get(User, owner_id)
    if user is None:
        raise SessionNotFoundError("Sesi pengguna tidak lagi valid.")

    rows = db.scalars(
        select(EncryptedFieldRow).where(EncryptedFieldRow.owner_id == owner_id)
    ).all()
    by_field = {row.field_name: row for row in rows}
    username_row = by_field.get(USERNAME_FIELD)
    password_row = by_field.get(PASSWORD_FIELD)
    if username_row is None or password_row is None:
        raise CorruptCredentialDataError(
            "Data terenkripsi tidak lengkap atau tidak ditemukan untuk akun ini."
        )

    try:
        username_plain = crypto.decrypt_text(_row_to_encrypted_field(username_row))
    except RecordCryptoError as exc:
        logger.warning("Failed to decode username metadata record_id=%s", username_row.id)
        raise CorruptCredentialDataError(
            "Data nama pengguna terenkripsi tidak dapat didekode dengan kunci aktif."
        ) from exc

    note_row = by_field.get(PROFILE_NOTE_FIELD)
    return CredentialsOverviewView(
        user_id=user.id,
        username=username_plain,
        username_record=_row_to_metadata_view(username_row),
        password_record=_row_to_metadata_view(password_row),
        profile_note_record=_row_to_metadata_view(note_row) if note_row is not None else None,
    )


def change_user_password(
    db: Session,
    crypto: ClefiaRecordService,
    *,
    owner_id: uuid.UUID,
    current_password: str,
    new_password: str,
    keep_session_id: uuid.UUID | None = None,
) -> EncryptedFieldRow:
    """Verify current password via CLEFIA-CTR decryption, then re-encrypt with a fresh nonce."""
    if not isinstance(current_password, str) or not current_password:
        raise InvalidCredentialsError("Kata sandi saat ini salah.")

    password_row = db.scalar(
        select(EncryptedFieldRow).where(
            EncryptedFieldRow.owner_id == owner_id,
            EncryptedFieldRow.field_name == PASSWORD_FIELD,
        )
    )
    if password_row is None:
        raise CorruptCredentialDataError("Data kata sandi terenkripsi tidak ditemukan.")

    previous_nonce = password_row.nonce
    try:
        stored_pw = crypto.decrypt_text(_row_to_encrypted_field(password_row))
    except RecordCryptoError as exc:
        logger.warning("Failed to decode password record_id=%s", password_row.id)
        raise CorruptCredentialDataError(
            "Data kata sandi terenkripsi tidak dapat didekode."
        ) from exc

    matches = secrets.compare_digest(stored_pw.encode("utf-8"), current_password.encode("utf-8"))
    if not matches:
        del stored_pw
        raise InvalidCredentialsError("Kata sandi saat ini salah.")

    validated_new = validate_password(new_password)
    same_as_old = secrets.compare_digest(
        stored_pw.encode("utf-8"),
        validated_new.encode("utf-8"),
    )
    del stored_pw
    if same_as_old:
        raise ValidationError("Kata sandi baru harus berbeda dari kata sandi saat ini.")

    updated = _upsert_encrypted_field(
        db,
        crypto,
        owner_id=owner_id,
        field_name=PASSWORD_FIELD,
        plaintext=validated_new,
        allow_empty=False,
        avoid_nonce=previous_nonce,
    )

    if keep_session_id is not None:
        db.execute(
            delete(UserSession).where(
                UserSession.user_id == owner_id,
                UserSession.id != keep_session_id,
            )
        )
        db.commit()
    return updated


def save_profile_note(
    db: Session,
    crypto: ClefiaRecordService,
    *,
    owner_id: uuid.UUID,
    note_text: str,
    field_name: str = PROFILE_NOTE_FIELD,
) -> EncryptedFieldRow:
    """Encrypt and upsert a synthetic profile note for owner_id with a fresh nonce."""
    if not isinstance(note_text, str):
        raise ValidationError("Catatan profil harus berupa teks.")
    if len(note_text) > _PROFILE_NOTE_MAX_CHARS:
        raise ValidationError(
            f"Catatan profil maksimal {_PROFILE_NOTE_MAX_CHARS} karakter."
        )
    return _upsert_encrypted_field(
        db,
        crypto,
        owner_id=owner_id,
        field_name=field_name,
        plaintext=note_text,
        allow_empty=True,
    )


def read_profile_note_for_owner(
    db: Session,
    crypto: ClefiaRecordService,
    *,
    owner_id: uuid.UUID,
    field_name: str = PROFILE_NOTE_FIELD,
) -> ProfileNoteView | None:
    """Fetch and decrypt owner_id's encrypted profile note field (owner-scoped)."""
    row = db.scalar(
        select(EncryptedFieldRow).where(
            EncryptedFieldRow.owner_id == owner_id,
            EncryptedFieldRow.field_name == field_name,
        )
    )
    if row is None:
        return None

    try:
        plaintext_note = crypto.decrypt_text(_row_to_encrypted_field(row))
    except RecordCryptoError as exc:
        logger.warning("Failed to decode profile note record_id=%s", row.id)
        raise CorruptCredentialDataError(
            "Catatan profil terenkripsi tidak dapat didekode (format/UTF-8 tidak valid "
            "atau kunci tidak cocok)."
        ) from exc

    return ProfileNoteView(
        field_name=row.field_name,
        plaintext_note=plaintext_note,
        key_id=row.key_id,
        algorithm_version=row.algorithm_version,
        nonce_hex=row.nonce.hex(),
        ciphertext_hex=row.ciphertext.hex(),
        ciphertext_b64=base64.b64encode(row.ciphertext).decode("ascii"),
        ciphertext_len_bytes=len(row.ciphertext),
        updated_at=_ensure_utc(row.updated_at),
    )
