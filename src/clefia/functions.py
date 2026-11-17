"""CLEFIA byte/word conversions, F0/F1 round functions, and DoubleSwap (Sigma).

References:
    - RFC 6114, Section 2 (Notations) & Section 5.1 (big-endian word packing).
    - RFC 6114, Section 4.2 (F-Functions F0 and F1).
    - RFC 6114, Section 6.1 (DoubleSwap Function Sigma).
"""

from __future__ import annotations

from collections.abc import Sequence

from clefia.field import _require_uint, mul_m0, mul_m1
from clefia.sboxes import S0, S1

_UINT128_MASK: int = (1 << 128) - 1
_UINT64_MASK: int = (1 << 64) - 1
_UINT57_MASK: int = (1 << 57) - 1
_UINT7_MASK: int = 0x7F


def word_to_bytes(word: int) -> tuple[int, int, int, int]:
    """Split a 32-bit unsigned word into four 8-bit integers (MSB first)."""
    w = _require_uint(word, 32, "word")
    return (
        (w >> 24) & 0xFF,
        (w >> 16) & 0xFF,
        (w >> 8) & 0xFF,
        w & 0xFF,
    )


def bytes_to_word(b0: int, b1: int, b2: int, b3: int) -> int:
    """Pack four 8-bit integers (MSB first) into a 32-bit unsigned word."""
    return (
        (_require_uint(b0, 8, "b0") << 24)
        | (_require_uint(b1, 8, "b1") << 16)
        | (_require_uint(b2, 8, "b2") << 8)
        | _require_uint(b3, 8, "b3")
    )


def bytes_to_words128(data: bytes) -> tuple[int, int, int, int]:
    """Convert a 16-byte block/key into four 32-bit big-endian words.

    Raises TypeError if data is not bytes/bytearray and ValueError if length != 16.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Expected bytes or bytearray, got {type(data).__name__}")
    if len(data) != 16:
        raise ValueError(f"Expected exactly 16 bytes (128 bits), got {len(data)} bytes")
    raw = bytes(data)
    return (
        int.from_bytes(raw[0:4], "big"),
        int.from_bytes(raw[4:8], "big"),
        int.from_bytes(raw[8:12], "big"),
        int.from_bytes(raw[12:16], "big"),
    )


def words128_to_bytes(words: Sequence[int]) -> bytes:
    """Serialize four 32-bit big-endian words into a 16-byte block."""
    if len(words) != 4:
        raise ValueError(f"Expected exactly 4 32-bit words, got {len(words)}")
    return b"".join(
        _require_uint(w, 32, f"words[{i}]").to_bytes(4, "big") for i, w in enumerate(words)
    )


def words_to_int128(words: Sequence[int]) -> int:
    """Pack four 32-bit big-endian words into a 128-bit integer (words[0] is MSB)."""
    if len(words) != 4:
        raise ValueError(f"Expected exactly 4 32-bit words, got {len(words)}")
    w0 = _require_uint(words[0], 32, "words[0]")
    w1 = _require_uint(words[1], 32, "words[1]")
    w2 = _require_uint(words[2], 32, "words[2]")
    w3 = _require_uint(words[3], 32, "words[3]")
    return (w0 << 96) | (w1 << 64) | (w2 << 32) | w3


def int128_to_words(value: int) -> tuple[int, int, int, int]:
    """Split a 128-bit unsigned integer into four 32-bit big-endian words."""
    v = _require_uint(value, 128, "value")
    return (
        (v >> 96) & 0xFFFFFFFF,
        (v >> 64) & 0xFFFFFFFF,
        (v >> 32) & 0xFFFFFFFF,
        v & 0xFFFFFFFF,
    )


def F0(round_key: int, word: int) -> int:
    """Apply CLEFIA F-function F0(RK, x) = M0 * (S0, S1, S0, S1)(RK XOR x)."""
    rk = _require_uint(round_key, 32, "round_key")
    x = _require_uint(word, 32, "word")
    t = rk ^ x
    t0, t1, t2, t3 = word_to_bytes(t)
    s_vec = (S0[t0], S1[t1], S0[t2], S1[t3])
    y0, y1, y2, y3 = mul_m0(s_vec)
    return bytes_to_word(y0, y1, y2, y3)


def F1(round_key: int, word: int) -> int:
    """Apply CLEFIA F-function F1(RK, x) = M1 * (S1, S0, S1, S0)(RK XOR x)."""
    rk = _require_uint(round_key, 32, "round_key")
    x = _require_uint(word, 32, "word")
    t = rk ^ x
    t0, t1, t2, t3 = word_to_bytes(t)
    s_vec = (S1[t0], S0[t1], S1[t2], S0[t3])
    y0, y1, y2, y3 = mul_m1(s_vec)
    return bytes_to_word(y0, y1, y2, y3)


def double_swap(value: int) -> int:
    """Apply the CLEFIA 128-bit DoubleSwap permutation Sigma(X).

    From RFC 6114 Section 6.1 (bit 0 is MSB, bit 127 is LSB):
        Sigma(X) = X[7..63] || X[121..127] || X[0..6] || X[64..120]
    """
    x = _require_uint(value, 128, "value")
    x_0_6 = (x >> 121) & _UINT7_MASK
    x_7_63 = (x >> 64) & _UINT57_MASK
    x_64_120 = (x >> 7) & _UINT57_MASK
    x_121_127 = x & _UINT7_MASK
    return ((x_7_63 << 71) | (x_121_127 << 64) | (x_0_6 << 57) | x_64_120) & _UINT128_MASK


def double_swap_words(words: Sequence[int]) -> tuple[int, int, int, int]:
    """Apply DoubleSwap Sigma to a 4-word 128-bit state."""
    return int128_to_words(double_swap(words_to_int128(words)))
