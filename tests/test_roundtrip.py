"""Deterministic random round-trip, boundary, and input-validation tests (T-003, T-004)."""

import random

import pytest

from clefia.cipher import decrypt_block, encrypt_block


def test_1000_seeded_random_roundtrips_t003() -> None:
    """T-003: decrypt_block(K, encrypt_block(K, P)) == P for 1,000 seeded pairs."""
    rng = random.Random(20261115)
    for _ in range(1000):
        key = rng.randbytes(16)
        plaintext = rng.randbytes(16)
        ciphertext = encrypt_block(key, plaintext)
        assert len(ciphertext) == 16
        assert decrypt_block(key, ciphertext) == plaintext


def test_boundary_blocks_and_keys() -> None:
    """Verify all-zero, all-one, incremental, and high-bit boundary blocks/keys."""
    zero16 = b"\x00" * 16
    ones16 = b"\xff" * 16
    incr16 = bytes(range(16))
    msb16 = b"\x80" + b"\x00" * 15
    lsb16 = b"\x00" * 15 + b"\x01"

    cases = [
        (zero16, zero16),
        (zero16, ones16),
        (ones16, zero16),
        (ones16, ones16),
        (incr16, incr16),
        (msb16, lsb16),
        (lsb16, msb16),
    ]
    for key, plaintext in cases:
        ct = encrypt_block(key, plaintext)
        assert len(ct) == 16
        assert ct != plaintext
        assert decrypt_block(key, ct) == plaintext


def test_wrong_block_and_key_sizes_t004() -> None:
    """T-004: Reject keys or blocks of incorrect length or wrong type."""
    valid16 = b"\x11" * 16
    for bad_len in (0, 1, 15, 17, 24, 32):
        bad = b"\x00" * bad_len
        with pytest.raises(ValueError):
            encrypt_block(bad, valid16)
        with pytest.raises(ValueError):
            encrypt_block(valid16, bad)
        with pytest.raises(ValueError):
            decrypt_block(bad, valid16)
        with pytest.raises(ValueError):
            decrypt_block(valid16, bad)

    with pytest.raises(TypeError):
        encrypt_block("00" * 16, valid16)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        decrypt_block(valid16, "00" * 16)  # type: ignore[arg-type]
