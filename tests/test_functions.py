"""Unit tests for byte/word conversions, F0/F1, GFN4/GFNINV4, and DoubleSwap."""

import random

import pytest

from clefia.functions import (
    F0,
    F1,
    bytes_to_word,
    bytes_to_words128,
    double_swap,
    double_swap_words,
    int128_to_words,
    word_to_bytes,
    words128_to_bytes,
    words_to_int128,
)
from clefia.gfn import gfn4, gfn4_inv


def test_byte_word_conversions_and_validation() -> None:
    """Confirm MSB-first big-endian packing/unpacking and strict length validation."""
    raw = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    words = bytes_to_words128(raw)
    assert words == (0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F)
    assert words128_to_bytes(words) == raw

    assert word_to_bytes(0x00010203) == (0x00, 0x01, 0x02, 0x03)
    assert bytes_to_word(0x00, 0x01, 0x02, 0x03) == 0x00010203

    as_int = words_to_int128(words)
    assert as_int == 0x000102030405060708090A0B0C0D0E0F
    assert int128_to_words(as_int) == words

    with pytest.raises(ValueError):
        bytes_to_words128(b"\x00" * 15)
    with pytest.raises(ValueError):
        bytes_to_words128(b"\x00" * 17)
    with pytest.raises(TypeError):
        bytes_to_words128("000102030405060708090a0b0c0d0e0f")  # type: ignore[arg-type]


def test_f0_and_f1_against_rfc6114_appendix_b_rounds() -> None:
    """Verify F0 and F1 outputs on RFC 6114 Appendix B 128-bit intermediate rounds."""
    # Round 1
    assert F0(0xF3E6CEF9, 0x00010203) == 0x547A3193
    assert F1(0x8DF75E38, 0x08090A0B) == 0xABF12070
    # Round 2
    assert F0(0x41C06256, 0xAF91EA58) == 0xF51CEBB3
    assert F1(0x640AC51B, 0x1C56B7F7) == 0x82DFE347
    # Round 18
    assert F0(0xB19D0554, 0xDE2BF2FD) == 0xAC7738F2
    assert F1(0x5142F434, 0xF1298555) == 0x12D0C82D


def test_gfn4_and_gfn4_inv_roundtrip_and_rfc_18_rounds() -> None:
    """GFNINV_{4,r} must exactly invert GFN_{4,r}, and match RFC 6114 Appendix B."""
    rng = random.Random(20261115)
    for rounds in (1, 4, 12, 18):
        rks = [rng.getrandbits(32) for _ in range(2 * rounds)]
        state = (
            rng.getrandbits(32),
            rng.getrandbits(32),
            rng.getrandbits(32),
            rng.getrandbits(32),
        )
        out = gfn4(rks, state, rounds)
        recovered = gfn4_inv(rks, out, rounds)
        assert recovered == state

    # Exact 18-round GFN check using Appendix B 128-bit RK0..RK35
    rks_128 = [
        0xF3E6CEF9, 0x8DF75E38, 0x41C06256, 0x640AC51B,
        0x6A27E20A, 0x5A791B90, 0xE8C528DC, 0x00336EA3,
        0x59CD17C4, 0x28565583, 0x312A37CC, 0xC08ABD77,
        0x7E8E7EEC, 0x8BE7E949, 0xD3F463D6, 0xA0AAD6AA,
        0xE75EB039, 0x0D657EB9, 0x018002E2, 0x9117D009,
        0x9F98D11E, 0xBABEE8CF, 0xB0369EFA, 0xD3AAEF0D,
        0x3438F93B, 0xF9CEA4A0, 0x68DF9029, 0xB869B4A7,
        0x24D6406D, 0xE74BC550, 0x41C28193, 0x16DE4795,
        0xA34A20F5, 0x33265D14, 0xB19D0554, 0x5142F434,
    ]
    after_init_whitening = (0x00010203, 0xFBEBDBCB, 0x08090A0B, 0xB7A79787)
    before_final_whitening = (0xDE2BF2FD, 0xEC12FF89, 0xF1298555, 0x76B685FD)
    assert gfn4(rks_128, after_init_whitening, 18) == before_final_whitening
    assert gfn4_inv(rks_128, before_final_whitening, 18) == after_init_whitening

    with pytest.raises(ValueError):
        gfn4(rks_128[:-1], after_init_whitening, 18)
    with pytest.raises(ValueError):
        gfn4(rks_128, after_init_whitening[:3], 18)


def test_double_swap_exact_msb_bit_permutation() -> None:
    """Verify Sigma(X) bit-by-bit against RFC 6114 Section 6.1 (MSB = bit 0)."""
    # Test every single bit position (0 = MSB, 127 = LSB)
    seen_outputs: set[int] = set()
    for bit_idx in range(128):
        x = 1 << (127 - bit_idx)
        y = double_swap(x)
        assert y.bit_count() == 1
        seen_outputs.add(y)

        # Expected destination index (0 = MSB) in X[7..63] | X[121..127] | X[0..6] | X[64..120]:
        if 0 <= bit_idx <= 6:
            # Moves into segment starting at offset 57+7 = 64
            dest_idx = 64 + bit_idx
        elif 7 <= bit_idx <= 63:
            # Moves into segment starting at offset 0
            dest_idx = bit_idx - 7
        elif 64 <= bit_idx <= 120:
            # Moves into segment starting at offset 57+7+7 = 71
            dest_idx = 71 + (bit_idx - 64)
        else:  # 121 <= bit_idx <= 127
            # Moves into segment starting at offset 57
            dest_idx = 57 + (bit_idx - 121)

        assert y == (1 << (127 - dest_idx))

    assert len(seen_outputs) == 128

    # Also verify double_swap_words matches RFC Appendix B L -> RK_{4..7}:
    # RK_{4..7} = Sigma(L) ^ CON_128[28..31] ^ K
    l_words = (0x8F89A61B, 0x9DB9D0F3, 0x93E65627, 0xDA0D027E)
    con_28_31 = (0x511A3208, 0x3D3BFBE6, 0x1084B134, 0x7CA565A7)
    k_words = (0xFFEEDDCC, 0xBBAA9988, 0x77665544, 0x33221100)
    sigma_l = double_swap_words(l_words)
    rk_4_7 = tuple(s ^ c ^ k for s, c, k in zip(sigma_l, con_28_31, k_words, strict=True))
    assert rk_4_7 == (0x6A27E20A, 0x5A791B90, 0xE8C528DC, 0x00336EA3)
