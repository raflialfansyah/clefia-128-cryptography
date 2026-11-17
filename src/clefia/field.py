"""Finite-field arithmetic over GF(2^8) and GF(2^16) and CLEFIA diffusion matrices.

References:
    - RFC 6114, Section 4.4 (Diffusion Matrices): GF(2^8) modulo
      z^8 + z^4 + z^3 + z^2 + 1 (0x11D), matrices M0 and M1.
    - RFC 6114, Section 6.6 (Constant Values): GF(2^16) modulo
      z^16 + z^15 + z^13 + z^11 + z^5 + z^4 + 1 (0x1A831).
"""

from __future__ import annotations

GF8_MODULUS: int = 0x11D
GF16_MODULUS: int = 0x1A831

M0: tuple[tuple[int, int, int, int], ...] = (
    (0x01, 0x02, 0x04, 0x06),
    (0x02, 0x01, 0x06, 0x04),
    (0x04, 0x06, 0x01, 0x02),
    (0x06, 0x04, 0x02, 0x01),
)

M1: tuple[tuple[int, int, int, int], ...] = (
    (0x01, 0x08, 0x02, 0x0A),
    (0x08, 0x01, 0x0A, 0x02),
    (0x02, 0x0A, 0x01, 0x08),
    (0x0A, 0x02, 0x08, 0x01),
)


def _require_uint(value: int, bits: int, name: str) -> int:
    """Validate that value is a non-boolean integer within [0, 2^bits - 1]."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    max_val = (1 << bits) - 1
    if value < 0 or value > max_val:
        raise ValueError(f"{name} must be in 0..0x{max_val:x}, got {value:#x}")
    return value


def gf_mul8(a: int, b: int) -> int:
    """Multiply two elements in GF(2^8) modulo z^8 + z^4 + z^3 + z^2 + 1 (0x11D).

    Inputs and output are integers in 0..255 representing degree < 8 polynomials
    over GF(2) in standard MSB-first bit representation (0x02 corresponds to z).
    """
    x = _require_uint(a, 8, "a")
    y = _require_uint(b, 8, "b")
    result = 0
    reduction = GF8_MODULUS & 0xFF
    for _ in range(8):
        if y & 1:
            result ^= x
        carry = x & 0x80
        x = (x << 1) & 0xFF
        if carry:
            x ^= reduction
        y >>= 1
    return result


def gf_mul16(a: int, b: int) -> int:
    """Multiply two elements in GF(2^16) modulo 0x1A831.

    Modulus polynomial: z^16 + z^15 + z^13 + z^11 + z^5 + z^4 + 1 (RFC 6114 Sec 6.6).
    """
    x = _require_uint(a, 16, "a")
    y = _require_uint(b, 16, "b")
    result = 0
    reduction = GF16_MODULUS & 0xFFFF
    for _ in range(16):
        if y & 1:
            result ^= x
        carry = x & 0x8000
        x = (x << 1) & 0xFFFF
        if carry:
            x ^= reduction
        y >>= 1
    return result


def gf_inv16(a: int) -> int:
    """Return multiplicative inverse of nonzero element a in GF(2^16) mod 0x1A831.

    Uses Fermat's Little Theorem in GF(2^16): a^{-1} = a^(2^16 - 2).
    """
    x = _require_uint(a, 16, "a")
    if x == 0:
        raise ZeroDivisionError("0 has no multiplicative inverse in GF(2^16)")
    # 2^16 - 2 = 0xFFFE: binary 1111_1111_1111_1110 (15 ones followed by one zero)
    acc = 1
    base = x
    exponent = (1 << 16) - 2
    while exponent:
        if exponent & 1:
            acc = gf_mul16(acc, base)
        base = gf_mul16(base, base)
        exponent >>= 1
    return acc


def mul_matrix(
    matrix: tuple[tuple[int, int, int, int], ...],
    vec: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    """Multiply a 4x4 matrix over GF(2^8) by a 4-byte column vector."""
    if len(matrix) != 4 or any(len(row) != 4 for row in matrix):
        raise ValueError("matrix must be 4x4")
    if len(vec) != 4:
        raise ValueError("vec must have exactly 4 byte elements")
    validated_vec = tuple(_require_uint(v, 8, f"vec[{i}]") for i, v in enumerate(vec))
    out: list[int] = []
    for row in matrix:
        acc = 0
        for coeff, elem in zip(row, validated_vec, strict=True):
            acc ^= gf_mul8(coeff, elem)
        out.append(acc)
    return (out[0], out[1], out[2], out[3])


def mul_m0(vec: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Multiply 4-byte column vector by CLEFIA diffusion matrix M0 over GF(2^8)."""
    return mul_matrix(M0, vec)


def mul_m1(vec: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Multiply 4-byte column vector by CLEFIA diffusion matrix M1 over GF(2^8)."""
    return mul_matrix(M1, vec)
