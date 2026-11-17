"""CLEFIA-128 key schedule implementation.

References:
    - RFC 6114, Section 6.2 & Section 6.3 (Key Scheduling for a 128-Bit Key).
"""

from __future__ import annotations

from dataclasses import dataclass

from clefia.constants import CON_128
from clefia.functions import (
    bytes_to_words128,
    double_swap,
    int128_to_words,
    words128_to_bytes,
    words_to_int128,
)
from clefia.gfn import gfn4

KEY_BYTES_128: int = 16
WHITENING_KEY_WORDS: int = 4
ROUND_KEY_WORDS_128: int = 36


@dataclass(frozen=True, slots=True)
class KeySchedule128:
    """Expanded CLEFIA-128 key material: 4 whitening words and 36 round-key words."""

    whitening_keys: tuple[int, int, int, int]
    round_keys: tuple[int, ...]


def derive_intermediate_l(key: bytes) -> bytes:
    """Compute the 128-bit intermediate key L = GFN_{4,12}(CON_128[0..23], K)."""
    k_words = bytes_to_words128(key)
    l_words = gfn4(CON_128[:24], k_words, rounds=12)
    return words128_to_bytes(l_words)


def key_schedule_128(key: bytes) -> KeySchedule128:
    """Expand a 16-byte CLEFIA-128 key into WK0..WK3 and RK0..RK35.

    Matches RFC 6114 Section 6.3:
        1. L <- GFN_{4,12}(CON_128[0..23], K0..K3)
        2. WK0..WK3 <- K0..K3
        3. For i = 0..8:
             T <- L ^ (CON_128[24+4i] || ... || CON_128[24+4i+3])
             L <- Sigma(L)
             if i is odd: T <- T ^ K
             RK_{4i..4i+3} <- T
    """
    k0, k1, k2, k3 = bytes_to_words128(key)
    l_words = gfn4(CON_128[:24], (k0, k1, k2, k3), rounds=12)
    l_state = words_to_int128(l_words)

    round_keys: list[int] = []
    for i in range(9):
        l0, l1, l2, l3 = int128_to_words(l_state)
        base = 24 + 4 * i
        t0 = l0 ^ CON_128[base]
        t1 = l1 ^ CON_128[base + 1]
        t2 = l2 ^ CON_128[base + 2]
        t3 = l3 ^ CON_128[base + 3]

        l_state = double_swap(l_state)

        if i % 2 == 1:
            t0 ^= k0
            t1 ^= k1
            t2 ^= k2
            t3 ^= k3

        round_keys.extend((t0, t1, t2, t3))

    return KeySchedule128(
        whitening_keys=(k0, k1, k2, k3),
        round_keys=tuple(round_keys),
    )
