"""Unit tests for simplified CLEFIA-128-CTR record wrapper (CR-002: T-004, T-005, T-012)."""

import pytest

from clefia.key_schedule import key_schedule_128
from clefia.record_crypto import (
    ALGORITHM_VERSION,
    NONCE_SIZE,
    ClefiaKeyConfig,
    ClefiaRecordService,
    CounterOverflowError,
    EncryptedField,
    InvalidRecordFormatError,
    KeyConfigurationError,
    RecordDecodeError,
    clefia_ctr_crypt,
)

# Deterministic test-only keys (never used outside test suite)
TEST_ENC_HEX = "00112233445566778899aabbccddeeff"
ALT_ENC_HEX = "ffeeddccbbaa99887766554433221100"


def _make_service(
    enc_hex: str = TEST_ENC_HEX,
    key_id: str = "demo-v2",
) -> ClefiaRecordService:
    return ClefiaRecordService(ClefiaKeyConfig.from_hex(enc_hex, key_id))


def test_ctr_roundtrip_utf8_empty_and_multiblock_t004() -> None:
    """T-004: Empty note, boundary lengths, binary, and multi-block UTF-8 decrypt identically."""
    svc = _make_service()
    byte_samples = [
        b"",
        b"A",
        b"0123456789abcdef",  # exact 16 bytes
        b"0123456789abcdefX",  # 17 bytes (partial 2nd block)
        b"\x00\xff" * 64,
    ]
    for pt in byte_samples:
        enc = svc.encrypt_bytes(pt)
        assert enc.version == ALGORITHM_VERSION
        assert enc.key_id == "demo-v2"
        assert len(enc.nonce) == NONCE_SIZE
        assert len(enc.ciphertext) == len(pt)

        parsed = EncryptedField.from_bytes(enc.to_bytes())
        assert parsed == enc
        assert svc.decrypt_bytes(parsed) == pt

    text_samples = [
        "",
        "catatan_singkat",
        (
            "Halo kriptografi CLEFIA-128! "
            "Catatan profil berbahasa Indonesia dengan teks panjang > 16 byte."
        ),
        "KataSandiSimulasi!2026 🔐",
    ]
    for txt in text_samples:
        enc_txt = svc.encrypt_text(txt, key_id="demo-v2")
        assert svc.decrypt_text(enc_txt) == txt

    with pytest.raises(InvalidRecordFormatError):
        svc.encrypt_text("", key_id="demo-v2", allow_empty=False)


def test_two_encryptions_produce_distinct_nonces_and_ciphertexts_t005() -> None:
    """T-005: Encrypting identical plaintext twice yields distinct nonces and ciphertexts."""
    svc = _make_service()
    text = "Teks simulasi identik untuk pengujian keunikan nonce CLEFIA-CTR."
    enc1 = svc.encrypt_text(text, key_id="demo-v2")
    enc2 = svc.encrypt_text(text, key_id="demo-v2")

    assert enc1.nonce != enc2.nonce
    assert enc1.ciphertext != enc2.ciphertext
    assert svc.decrypt_text(enc1) == text
    assert svc.decrypt_text(enc2) == text


def test_ctr_counter_overflow_rejected() -> None:
    """CTR mode fails closed if 32-bit block counter would wrap past 0xFFFFFFFF."""
    ks = key_schedule_128(bytes.fromhex(TEST_ENC_HEX))
    nonce = b"\x01" * 12

    one_block = clefia_ctr_crypt(ks, nonce, b"A" * 16, initial_counter=0xFFFFFFFF)
    assert clefia_ctr_crypt(ks, nonce, one_block, initial_counter=0xFFFFFFFF) == b"A" * 16

    with pytest.raises(CounterOverflowError):
        clefia_ctr_crypt(ks, nonce, b"A" * 17, initial_counter=0xFFFFFFFF)

    with pytest.raises(CounterOverflowError):
        clefia_ctr_crypt(ks, nonce, b"A", initial_counter=0)


def test_key_config_structural_format_and_utf8_decode_errors_t012() -> None:
    """T-012: Validate key format, binary envelope parsing, version/key_id, and UTF-8 errors."""
    with pytest.raises(KeyConfigurationError):
        ClefiaKeyConfig.from_hex("<32_HEX_CHARS>", "demo-v2")
    with pytest.raises(KeyConfigurationError):
        ClefiaKeyConfig.from_hex("00" * 15, "demo-v2")
    with pytest.raises(KeyConfigurationError):
        ClefiaKeyConfig.from_hex("zz" * 16, "demo-v2")
    with pytest.raises(KeyConfigurationError):
        ClefiaKeyConfig.from_hex(TEST_ENC_HEX, "  ")

    svc = _make_service()
    with pytest.raises(KeyConfigurationError):
        svc.encrypt_text("halo", key_id="wrong-key-id")

    enc = svc.encrypt_text("teks valid", key_id="demo-v2")
    blob = enc.to_bytes()
    with pytest.raises(InvalidRecordFormatError):
        EncryptedField.from_bytes(b"BAD!" + blob[4:])
    with pytest.raises(InvalidRecordFormatError):
        EncryptedField.from_bytes(blob + b"\x00")
    with pytest.raises(InvalidRecordFormatError):
        EncryptedField.from_bytes(blob[:-1])
    with pytest.raises(InvalidRecordFormatError):
        EncryptedField(
            version=ALGORITHM_VERSION,
            key_id="demo-v2",
            nonce=b"\x00" * 11,
            ciphertext=b"a",
        )

    with pytest.raises(RecordDecodeError):
        svc.decrypt_text(
            EncryptedField(
                version=99,
                key_id="demo-v2",
                nonce=enc.nonce,
                ciphertext=enc.ciphertext,
            )
        )
    with pytest.raises(RecordDecodeError):
        svc.decrypt_text(
            EncryptedField(
                version=ALGORITHM_VERSION,
                key_id="other-id",
                nonce=enc.nonce,
                ciphertext=enc.ciphertext,
            )
        )

    # Raw invalid UTF-8 sequence decrypted via CTR must raise RecordDecodeError
    bad_utf8_enc = svc.encrypt_bytes(b"\xff\xfe\xfd")
    with pytest.raises(RecordDecodeError):
        svc.decrypt_text(bad_utf8_enc)


def test_documented_ctr_malleability_without_mac_t012() -> None:
    """T-012 negative check: Valid-looking modified CTR ciphertext decrypts without error."""
    svc = _make_service()
    enc = svc.encrypt_text("0000000000000000", key_id="demo-v2")

    # Flipping bit 0 of byte 0 turns ASCII '0' (0x30) into '1' (0x31) in CTR mode.
    flipped = bytearray(enc.ciphertext)
    flipped[0] ^= 0x01
    modified_field = EncryptedField(
        version=enc.version,
        key_id=enc.key_id,
        nonce=enc.nonce,
        ciphertext=bytes(flipped),
    )

    # Without a MAC, structural validation passes and plaintext silently changes!
    assert svc.decrypt_text(modified_field) == "1000000000000000"
