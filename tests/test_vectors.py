"""Mandatory official Sony/RFC 6114 CLEFIA-128 test vector and intermediate verification."""

from clefia.cipher import decrypt_block, encrypt_block, trace_encrypt_block
from clefia.key_schedule import derive_intermediate_l, key_schedule_128

OFFICIAL_KEY = bytes.fromhex("ffeeddccbbaa99887766554433221100")
OFFICIAL_PLAINTEXT = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
OFFICIAL_CIPHERTEXT = bytes.fromhex("de2bf2fd9b74aacdf1298555459494fd")


def test_official_clefia128_test_vector_t001() -> None:
    """T-001: Sony/RFC 6114 Appendix A 128-bit test vector encrypt & decrypt."""
    ciphertext = encrypt_block(OFFICIAL_KEY, OFFICIAL_PLAINTEXT)
    assert ciphertext == OFFICIAL_CIPHERTEXT
    assert ciphertext.hex() == "de2bf2fd9b74aacdf1298555459494fd"

    recovered = decrypt_block(OFFICIAL_KEY, OFFICIAL_CIPHERTEXT)
    assert recovered == OFFICIAL_PLAINTEXT


def test_rfc6114_appendix_b_intermediates_t002() -> None:
    """T-002: Verify RFC 6114 Appendix B L, WK, RK0..3, RK32..35, and round trace."""
    assert derive_intermediate_l(OFFICIAL_KEY).hex() == "8f89a61b9db9d0f393e65627da0d027e"

    ks = key_schedule_128(OFFICIAL_KEY)
    assert "".join(f"{w:08x}" for w in ks.whitening_keys) == "ffeeddccbbaa99887766554433221100"
    assert "".join(f"{w:08x}" for w in ks.round_keys[:4]) == "f3e6cef98df75e3841c06256640ac51b"
    assert "".join(f"{w:08x}" for w in ks.round_keys[32:36]) == "a34a20f533265d14b19d05545142f434"

    trace = trace_encrypt_block(OFFICIAL_KEY, OFFICIAL_PLAINTEXT)
    assert trace.after_initial_whitening == (0x00010203, 0xFBEBDBCB, 0x08090A0B, 0xB7A79787)
    assert len(trace.rounds) == 18

    # Round 1
    r1 = trace.rounds[0]
    assert r1.input_words == (0x00010203, 0xFBEBDBCB, 0x08090A0B, 0xB7A79787)
    assert (r1.f0_out, r1.f1_out) == (0x547A3193, 0xABF12070)

    # Round 9
    r9 = trace.rounds[8]
    assert r9.input_words == (0xBFD8DDE7, 0xB8EC058B, 0x81B85950, 0x1459A507)
    assert (r9.f0_out, r9.f1_out) == (0xE6D6501E, 0x6D5839B4)

    # Round 18
    r18 = trace.rounds[17]
    assert r18.input_words == (0xDE2BF2FD, 0x4065C77B, 0xF1298555, 0x64664DD0)
    assert (r18.f0_out, r18.f1_out) == (0xAC7738F2, 0x12D0C82D)

    assert trace.before_final_whitening == (0xDE2BF2FD, 0xEC12FF89, 0xF1298555, 0x76B685FD)
    assert trace.ciphertext == OFFICIAL_CIPHERTEXT
