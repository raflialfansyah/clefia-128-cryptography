"""Data transfer objects for authenticated profile and credential views (CR-002)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """Server-resolved principal hydrated by decrypting the owner's username record."""

    id: uuid.UUID
    username: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class ProfileNoteView:
    """Decrypted synthetic profile note alongside non-secret CTR ciphertext metadata."""

    field_name: str
    plaintext_note: str
    key_id: str
    algorithm_version: int
    nonce_hex: str
    ciphertext_hex: str
    ciphertext_b64: str
    ciphertext_len_bytes: int
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class EncryptedFieldMetadataView:
    """Non-secret CLEFIA-128-CTR ciphertext metadata (never exposes password plaintext)."""

    field_name: str
    algorithm: str
    mode: str
    key_id: str
    algorithm_version: int
    nonce_hex: str
    ciphertext_hex: str
    ciphertext_b64: str
    ciphertext_len_bytes: int
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class CredentialsOverviewView:
    """Authenticated owner's CLEFIA-128-CTR credential & profile-note metadata view."""

    user_id: uuid.UUID
    username: str
    username_record: EncryptedFieldMetadataView
    password_record: EncryptedFieldMetadataView
    profile_note_record: EncryptedFieldMetadataView | None
