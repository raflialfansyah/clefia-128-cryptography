"""CLEFIA-128 key schedule constant generation over GF(2^16).

References:
    - RFC 6114, Section 6.6 (Constant Values, Table 3, Table 4, Table 7).
"""

from __future__ import annotations

from clefia.field import gf_inv16, gf_mul16

# RFC 6114 Section 6.6:
# P(16) = (e - 2) * 2^16 (rounded/truncated hexadecimal constant)
# Q(16) = (pi - 3) * 2^16 (rounded/truncated hexadecimal constant)
P_16: int = 0xB7E1
Q_16: int = 0x243F
IV_128: int = 0x428A
CONSTANT_PAIRS_128: int = 30  # l_128 = 30 -> 60 32-bit constants


def _rotl16(value: int, shift: int) -> int:
    """Cyclic left shift of a 16-bit unsigned integer."""
    v = value & 0xFFFF
    s = shift % 16
    return ((v << s) | (v >> (16 - s))) & 0xFFFF


def generate_t_128() -> tuple[int, ...]:
    """Generate the 30 16-bit intermediate sequence values T_128[0..29]."""
    inv2 = gf_inv16(0x0002)
    t = IV_128
    seq: list[int] = []
    for _ in range(CONSTANT_PAIRS_128):
        seq.append(t)
        t = gf_mul16(t, inv2)
    return tuple(seq)


def generate_con_128() -> tuple[int, ...]:
    """Generate the 60 32-bit key-schedule constants CON_128[0..59].

    Follows RFC 6114 Section 6.6:
        CON_128[2i]     = (T_128[i] ^ P_16) || (~T_128[i] <<< 1)
        CON_128[2i + 1] = (~T_128[i] ^ Q_16) || (T_128[i] <<< 8)
        T_128[i + 1]    = T_128[i] * (0x0002^{-1}) in GF(2^16) mod 0x1A831
    """
    inv2 = gf_inv16(0x0002)
    t = IV_128
    constants: list[int] = []
    for _ in range(CONSTANT_PAIRS_128):
        t_not = t ^ 0xFFFF
        con_even = ((t ^ P_16) << 16) | _rotl16(t_not, 1)
        con_odd = ((t_not ^ Q_16) << 16) | _rotl16(t, 8)
        constants.append(con_even)
        constants.append(con_odd)
        t = gf_mul16(t, inv2)
    return tuple(constants)


T_128: tuple[int, ...] = generate_t_128()
CON_128: tuple[int, ...] = generate_con_128()
