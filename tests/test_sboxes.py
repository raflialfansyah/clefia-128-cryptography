"""Unit tests for CLEFIA S-boxes S0 and S1."""

import pytest

from clefia.sboxes import S0, S1, s0, s1


def test_sboxes_have_256_entries_and_are_bijective() -> None:
    """Both S0 and S1 must be 256-entry permutations of 0..255."""
    assert len(S0) == 256
    assert len(S1) == 256
    assert set(S0) == set(range(256))
    assert set(S1) == set(range(256))


def test_sboxes_rfc6114_spot_and_boundary_values() -> None:
    """Verify RFC 6114 Section 4.3 example and Appendix B Round 1/18 lookups."""
    # RFC 6114 Section 4.3 narrative example: S0(0xab) = 0x7e
    assert s0(0xAB) == 0x7E
    # Boundary corners
    assert s0(0x00) == 0x57
    assert s0(0xFF) == 0x8E
    assert s1(0x00) == 0x6C
    assert s1(0xFF) == 0x1D
    # RFC 6114 Appendix B Round 1:
    # F0 after key add = 0xf3e7ccfa -> after S = 0x290246e1
    assert (s0(0xF3), s1(0xE7), s0(0xCC), s1(0xFA)) == (0x29, 0x02, 0x46, 0xE1)
    # F1 after key add = 0x85fe5433 -> after S = 0x777de8e8
    assert (s1(0x85), s0(0xFE), s1(0x54), s0(0x33)) == (0x77, 0x7D, 0xE8, 0xE8)


def test_sboxes_reject_invalid_inputs() -> None:
    """Out-of-range or boolean byte inputs must raise."""
    for fn in (s0, s1):
        with pytest.raises(ValueError):
            fn(-1)
        with pytest.raises(ValueError):
            fn(256)
        with pytest.raises(TypeError):
            fn(False)
