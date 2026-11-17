"""Unit tests for GF(2^8), GF(2^16), and CLEFIA diffusion matrices M0 and M1."""

import random

import pytest

from clefia.field import (
    GF8_MODULUS,
    GF16_MODULUS,
    M0,
    M1,
    gf_inv16,
    gf_mul8,
    gf_mul16,
    mul_m0,
    mul_m1,
)


def test_field_polynomials() -> None:
    """Confirm CLEFIA specification moduli."""
    assert GF8_MODULUS == 0x11D
    assert GF16_MODULUS == 0x1A831


def test_gf_mul8_identities_and_reduction() -> None:
    """Verify GF(2^8) identity, zero, and reduction mod x^8 + x^4 + x^3 + x^2 + 1."""
    assert gf_mul8(0, 0xAB) == 0
    assert gf_mul8(0xAB, 0) == 0
    assert gf_mul8(1, 0xAB) == 0xAB
    assert gf_mul8(0xAB, 1) == 0xAB
    # z^7 * z = z^8 = z^4 + z^3 + z^2 + 1 = 0x1D
    assert gf_mul8(0x80, 0x02) == 0x1D
    # z^4 * z^4 = z^8 = 0x1D
    assert gf_mul8(0x10, 0x10) == 0x1D
    # 0x02 * 0xE1 = (0xC2 ^ 0x1D) = 0xDF
    assert gf_mul8(0x02, 0xE1) == 0xDF
    # 0x06 * 0xE1 = (0x02 * 0xE1) ^ (0x04 * 0xE1) = 0xDF ^ 0xA3 = 0x7C
    assert gf_mul8(0x06, 0xE1) == 0x7C


def test_gf_mul8_field_axioms() -> None:
    """Verify commutativity, associativity, and distributivity over XOR."""
    rng = random.Random(20261115)
    for _ in range(250):
        a = rng.randrange(256)
        b = rng.randrange(256)
        c = rng.randrange(256)
        assert gf_mul8(a, b) == gf_mul8(b, a)
        assert gf_mul8(gf_mul8(a, b), c) == gf_mul8(a, gf_mul8(b, c))
        assert gf_mul8(a, b ^ c) == (gf_mul8(a, b) ^ gf_mul8(a, c))


def test_gf_mul8_rejects_invalid_inputs() -> None:
    """Reject out-of-range or boolean arguments."""
    with pytest.raises(ValueError):
        gf_mul8(-1, 1)
    with pytest.raises(ValueError):
        gf_mul8(1, 256)
    with pytest.raises(TypeError):
        gf_mul8(True, 1)


def test_gf16_mul_and_inv_matches_rfc6114_t128_progression() -> None:
    """Verify GF(2^16) inverse and RFC 6114 Table 4 recurrence T_128[i+1] = T_128[i] * 2^{-1}."""
    inv2 = gf_inv16(0x0002)
    assert gf_mul16(0x0002, inv2) == 1
    # RFC 6114 Table 4 first few values of T_128[i]:
    t_expected = [0x428A, 0x2145, 0xC4BA, 0x625D, 0xE536, 0x729B, 0xED55, 0xA2B2]
    cur = t_expected[0]
    for nxt in t_expected[1:]:
        cur = gf_mul16(cur, inv2)
        assert cur == nxt

    with pytest.raises(ZeroDivisionError):
        gf_inv16(0)


def test_matrices_m0_and_m1_rfc_round1_values() -> None:
    """Verify M0 and M1 matrix multiplications against RFC 6114 Appendix B Round 1."""
    # Round 1 after S -> after M:
    # F0: 0x290246e1 -> 0x547a3193
    assert mul_m0((0x29, 0x02, 0x46, 0xE1)) == (0x54, 0x7A, 0x31, 0x93)
    # F1: 0x777de8e8 -> 0xabf12070
    assert mul_m1((0x77, 0x7D, 0xE8, 0xE8)) == (0xAB, 0xF1, 0x20, 0x70)
    assert len(M0) == 4 and len(M1) == 4


def test_matrices_are_involutions_and_mds() -> None:
    """Both M0 and M1 are involutory (M^2 = I) and MDS (branch number 5)."""
    rng = random.Random(12345)
    for _ in range(100):
        vec = tuple(rng.randrange(256) for _ in range(4))
        assert mul_m0(mul_m0(vec)) == vec
        assert mul_m1(mul_m1(vec)) == vec

    # Check MDS branch number >= 5 for all weight-1 vectors (255 * 4 vectors)
    for pos in range(4):
        for val in range(1, 256):
            vec_list = [0, 0, 0, 0]
            vec_list[pos] = val
            vec = (vec_list[0], vec_list[1], vec_list[2], vec_list[3])
            out0 = mul_m0(vec)
            out1 = mul_m1(vec)
            assert sum(1 for b in out0 if b != 0) == 4
            assert sum(1 for b in out1 if b != 0) == 4

    with pytest.raises(ValueError):
        mul_m0((1, 2, 3))  # type: ignore[arg-type]
