"""Variable-length CLEFIA-128-CTR record encryption wrapper (no MAC/integrity tag).

Design choices (CR-002 educational demonstrator):
    - Mode: CLEFIA-128 in Counter (CTR) mode using a fresh 96-bit (12-byte) random
      nonce via secrets.token_bytes(12) and a 32-bit big-endian counter starting at 1.
    - Limitation: CTR encryption without an authentication tag is malleable and does
      not detect intentional modification of stored ciphertext. Structural validation
      and strict UTF-8 decoding catch malformed inputs only, never integrity attacks.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from clefia.cipher import BLOCK_SIZE, KEY_SIZE, encrypt_block_with_schedule
from clefia.key_schedule import KeySchedule128, key_schedule_128

ALGORITHM_VERSION: int = 2
NONCE_SIZE: int = 12
MAX_CTR_COUNTER: int = 0xFFFFFFFF  # 32-bit counter 1..2^32-1 -> max 2^32 - 1 blocks

_SERIAL_MAGIC: bytes = b"CLF2"


class RecordCryptoError(Exception):
    """Base exception for CLEFIA-128 CTR record wrapper errors."""


class CounterOverflowError(RecordCryptoError):
    """Raised when the 32-bit CTR block counter would exceed 0xFFFFFFFF."""


class InvalidRecordFormatError(RecordCryptoError):
    """Raised when serialized record bytes, headers, nonces, or key metadata are invalid."""


class KeyConfigurationError(RecordCryptoError):
    """Raised when encryption keys or key identifiers fail validation."""


class RecordDecodeError(RecordCryptoError):
    """Raised when decrypted bytes fail strict UTF-8 decoding or version/key validation."""


def _validate_non_empty_str(value: str, name: str, max_bytes: int = 256) -> bytes:
    """Validate non-empty string field and return its UTF-8 encoding."""
    if not isinstance(value, str):
        raise InvalidRecordFormatError(f"{name} must be a str, got {type(value).__name__}")
    if not value or value.strip() != value:
        raise InvalidRecordFormatError(f"{name} must be non-empty without leading/trailing spaces")
    encoded = value.encode("utf-8")
    if len(encoded) > max_bytes:
        raise InvalidRecordFormatError(f"{name} UTF-8 length exceeds {max_bytes} bytes")
    return encoded


def _require_bytes(value: bytes, expected_len: int | None, name: str) -> bytes:
    """Validate bytes input and optional exact byte length."""
    if not isinstance(value, (bytes, bytearray)):
        raise InvalidRecordFormatError(f"{name} must be bytes, got {type(value).__name__}")
    raw = bytes(value)
    if expected_len is not None and len(raw) != expected_len:
        raise InvalidRecordFormatError(
            f"{name} must be exactly {expected_len} bytes, got {len(raw)}"
        )
    return raw


@dataclass(frozen=True, slots=True)
class ClefiaKeyConfig:
    """Validated 128-bit encryption key configuration for CLEFIA-128-CTR."""

    enc_key: bytes
    key_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.enc_key, (bytes, bytearray)) or len(self.enc_key) != KEY_SIZE:
            raise KeyConfigurationError(f"enc_key must be exactly {KEY_SIZE} bytes")
        object.__setattr__(self, "enc_key", bytes(self.enc_key))

        if (
            not isinstance(self.key_id, str)
            or not self.key_id
            or self.key_id.strip() != self.key_id
        ):
            raise KeyConfigurationError(
                "key_id must be a non-empty string without outer whitespace"
            )
        if len(self.key_id.encode("utf-8")) > 128:
            raise KeyConfigurationError("key_id must be <= 128 UTF-8 bytes")

    @classmethod
    def from_hex(cls, enc_key_hex: str, key_id: str) -> ClefiaKeyConfig:
        """Parse and validate a hex-encoded 128-bit CLEFIA encryption key."""
        if not isinstance(enc_key_hex, str):
            raise KeyConfigurationError("CLEFIA_ENC_KEY_HEX must be a string")
        try:
            enc_key = bytes.fromhex(enc_key_hex)
        except ValueError as exc:
            raise KeyConfigurationError("CLEFIA_ENC_KEY_HEX is not valid hexadecimal") from exc
        if len(enc_key_hex) != KEY_SIZE * 2 or len(enc_key) != KEY_SIZE:
            raise KeyConfigurationError(
                f"CLEFIA_ENC_KEY_HEX must be {KEY_SIZE * 2} hex characters ({KEY_SIZE} bytes)"
            )
        return cls(enc_key=enc_key, key_id=key_id)


@dataclass(frozen=True, slots=True)
class EncryptedField:
    """Versioned CLEFIA-128-CTR encrypted payload (no integrity tag)."""

    version: int
    key_id: str
    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise InvalidRecordFormatError("version must be an int")
        if self.version < 1 or self.version > 0xFFFF:
            raise InvalidRecordFormatError("version out of uint16 range")
        _validate_non_empty_str(self.key_id, "key_id", max_bytes=128)
        object.__setattr__(self, "nonce", _require_bytes(self.nonce, NONCE_SIZE, "nonce"))
        object.__setattr__(self, "ciphertext", _require_bytes(self.ciphertext, None, "ciphertext"))

    def to_bytes(self) -> bytes:
        """Serialize field envelope into length-prefixed binary representation."""
        key_id_bytes = self.key_id.encode("utf-8")
        return b"".join(
            [
                _SERIAL_MAGIC,
                self.version.to_bytes(2, "big"),
                len(key_id_bytes).to_bytes(2, "big"),
                key_id_bytes,
                self.nonce,
                len(self.ciphertext).to_bytes(4, "big"),
                self.ciphertext,
            ]
        )

    @classmethod
    def from_bytes(cls, blob: bytes) -> EncryptedField:
        """Parse canonical binary representation back into an EncryptedField."""
        raw = _require_bytes(blob, None, "blob")
        min_len = len(_SERIAL_MAGIC) + 2 + 2 + NONCE_SIZE + 4
        if len(raw) < min_len:
            raise InvalidRecordFormatError("Serialized record is shorter than minimum header")
        if raw[:4] != _SERIAL_MAGIC:
            raise InvalidRecordFormatError("Invalid serialized record magic header")

        offset = 4
        version = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2

        key_id_len = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2
        if key_id_len == 0 or offset + key_id_len + NONCE_SIZE + 4 > len(raw):
            raise InvalidRecordFormatError("Malformed key_id length in serialized record")
        try:
            key_id = raw[offset : offset + key_id_len].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidRecordFormatError("key_id is not valid UTF-8") from exc
        offset += key_id_len

        nonce = raw[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE

        ct_len = int.from_bytes(raw[offset : offset + 4], "big")
        offset += 4
        if offset + ct_len != len(raw):
            raise InvalidRecordFormatError("Ciphertext length mismatch in serialized record")
        ciphertext = raw[offset : offset + ct_len]

        return cls(
            version=version,
            key_id=key_id,
            nonce=nonce,
            ciphertext=ciphertext,
        )


def clefia_ctr_crypt(
    schedule: KeySchedule128,
    nonce: bytes,
    data: bytes,
    *,
    initial_counter: int = 1,
) -> bytes:
    """Apply CLEFIA-128-CTR keystream XOR to arbitrary-length bytes.

    Counter block format (16 bytes):
        nonce (12 bytes) || counter (4 bytes big-endian, starting at initial_counter >= 1).
    Rejects if the 32-bit counter would wrap past 0xFFFFFFFF.
    """
    nonce_bytes = _require_bytes(nonce, NONCE_SIZE, "nonce")
    payload = _require_bytes(data, None, "data")
    if isinstance(initial_counter, bool) or not isinstance(initial_counter, int):
        raise CounterOverflowError("initial_counter must be an integer")
    if initial_counter < 1 or initial_counter > MAX_CTR_COUNTER:
        raise CounterOverflowError("initial_counter must be in 1..0xFFFFFFFF")

    if not payload:
        return b""

    num_blocks = (len(payload) + BLOCK_SIZE - 1) // BLOCK_SIZE
    last_counter = initial_counter + num_blocks - 1
    if last_counter > MAX_CTR_COUNTER:
        raise CounterOverflowError(
            f"CTR 32-bit counter overflow: need {num_blocks} blocks from {initial_counter}"
        )

    out = bytearray(len(payload))
    for block_idx in range(num_blocks):
        counter = initial_counter + block_idx
        counter_block = nonce_bytes + counter.to_bytes(4, "big")
        keystream = encrypt_block_with_schedule(schedule, counter_block)
        start = block_idx * BLOCK_SIZE
        chunk = payload[start : start + BLOCK_SIZE]
        for i, byte_val in enumerate(chunk):
            out[start + i] = byte_val ^ keystream[i]
    return bytes(out)


class ClefiaRecordService:
    """CLEFIA-128-CTR encryption/decryption service for variable-length UTF-8 text.

    Note: CTR mode alone does not detect intentional ciphertext manipulation.
    """

    def __init__(self, config: ClefiaKeyConfig) -> None:
        self._config = config
        self._schedule: KeySchedule128 = key_schedule_128(config.enc_key)

    @property
    def key_id(self) -> str:
        """Return configured key identifier metadata."""
        return self._config.key_id

    def encrypt_bytes(self, plaintext: bytes, *, allow_empty: bool = True) -> EncryptedField:
        """Encrypt arbitrary-length bytes under a fresh random 96-bit nonce."""
        raw_plaintext = _require_bytes(plaintext, None, "plaintext")
        if not allow_empty and not raw_plaintext:
            raise InvalidRecordFormatError("Empty plaintext is not permitted for this field")

        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = clefia_ctr_crypt(self._schedule, nonce, raw_plaintext, initial_counter=1)
        return EncryptedField(
            version=ALGORITHM_VERSION,
            key_id=self._config.key_id,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    def decrypt_bytes(self, encrypted: EncryptedField) -> bytes:
        """Validate envelope metadata structurally and decrypt CLEFIA-128-CTR payload."""
        if not isinstance(encrypted, EncryptedField):
            raise InvalidRecordFormatError("encrypted must be an EncryptedField instance")
        if encrypted.version != ALGORITHM_VERSION:
            raise RecordDecodeError(f"Unsupported record version: {encrypted.version}")
        if not secrets.compare_digest(
            encrypted.key_id.encode("utf-8"),
            self._config.key_id.encode("utf-8"),
        ):
            raise RecordDecodeError("Record key_id does not match active configuration")

        return clefia_ctr_crypt(
            self._schedule,
            encrypted.nonce,
            encrypted.ciphertext,
            initial_counter=1,
        )

    def encrypt_text(
        self,
        plaintext: str,
        *,
        key_id: str | None = None,
        allow_empty: bool = True,
    ) -> EncryptedField:
        """Encode UTF-8 text strictly and encrypt with CLEFIA-128-CTR."""
        if not isinstance(plaintext, str):
            raise InvalidRecordFormatError("plaintext must be a str")
        if key_id is not None and not secrets.compare_digest(
            key_id.encode("utf-8"),
            self._config.key_id.encode("utf-8"),
        ):
            raise KeyConfigurationError("Requested key_id does not match service configuration")
        encoded = plaintext.encode("utf-8", errors="strict")
        return self.encrypt_bytes(encoded, allow_empty=allow_empty)

    def decrypt_text(self, encrypted: EncryptedField) -> str:
        """Decrypt CLEFIA-128-CTR ciphertext and decode UTF-8 strictly."""
        raw = self.decrypt_bytes(encrypted)
        try:
            return raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise RecordDecodeError("Decrypted payload is not valid UTF-8") from exc
