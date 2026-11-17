"""CLEFIA-128 block encryption and decryption (18-round GFN_{4,18}).

References:
    - RFC 6114, Section 5.1 (Encryption/Decryption) and Section 5.2 (18 rounds for 128-bit key).
"""

from __future__ import annotations

from dataclasses import dataclass

from clefia.functions import F0, F1, bytes_to_words128, words128_to_bytes
from clefia.gfn import gfn4, gfn4_inv
from clefia.key_schedule import KeySchedule128, key_schedule_128

BLOCK_SIZE: int = 16
KEY_SIZE: int = 16
ROUNDS_128: int = 18


@dataclass(frozen=True, slots=True)
class RoundTrace:
    """Single-round intermediate trace for educational/test inspection only."""

    round_number: int
    input_words: tuple[int, int, int, int]
    rk_even: int
    rk_odd: int
    f0_out: int
    f1_out: int


@dataclass(frozen=True, slots=True)
class EncryptionTrace:
    """Full CLEFIA-128 block encryption trace for test and educational inspection."""

    after_initial_whitening: tuple[int, int, int, int]
    rounds: tuple[RoundTrace, ...]
    before_final_whitening: tuple[int, int, int, int]
    ciphertext: bytes


def encrypt_block_with_schedule(schedule: KeySchedule128, plaintext: bytes) -> bytes:
    """Encrypt a single 16-byte block using a precomputed CLEFIA-128 key schedule."""
    if len(schedule.whitening_keys) != 4 or len(schedule.round_keys) != 2 * ROUNDS_128:
        raise ValueError("Invalid CLEFIA-128 key schedule dimensions")
    p0, p1, p2, p3 = bytes_to_words128(plaintext)
    wk0, wk1, wk2, wk3 = schedule.whitening_keys

    # RFC 6114 Section 5.1 ENCr Step 1: initial input whitening on branches 1 and 3
    t0, t1, t2, t3 = p0, p1 ^ wk0, p2, p3 ^ wk1
    # Step 2: 18-round 4-branch Generalized Feistel Network
    t0, t1, t2, t3 = gfn4(schedule.round_keys, (t0, t1, t2, t3), ROUNDS_128)
    # Step 3: final output whitening on branches 1 and 3
    c0, c1, c2, c3 = t0, t1 ^ wk2, t2, t3 ^ wk3
    return words128_to_bytes((c0, c1, c2, c3))


def decrypt_block_with_schedule(schedule: KeySchedule128, ciphertext: bytes) -> bytes:
    """Decrypt a single 16-byte block using a precomputed CLEFIA-128 key schedule."""
    if len(schedule.whitening_keys) != 4 or len(schedule.round_keys) != 2 * ROUNDS_128:
        raise ValueError("Invalid CLEFIA-128 key schedule dimensions")
    c0, c1, c2, c3 = bytes_to_words128(ciphertext)
    wk0, wk1, wk2, wk3 = schedule.whitening_keys

    # RFC 6114 Section 5.1 DECr Step 1: undo final whitening on branches 1 and 3
    t0, t1, t2, t3 = c0, c1 ^ wk2, c2, c3 ^ wk3
    # Step 2: inverse 18-round GFN
    t0, t1, t2, t3 = gfn4_inv(schedule.round_keys, (t0, t1, t2, t3), ROUNDS_128)
    # Step 3: undo initial whitening on branches 1 and 3
    p0, p1, p2, p3 = t0, t1 ^ wk0, t2, t3 ^ wk1
    return words128_to_bytes((p0, p1, p2, p3))


def encrypt_block(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt one 16-byte plaintext block with a 16-byte key under CLEFIA-128."""
    schedule = key_schedule_128(key)
    return encrypt_block_with_schedule(schedule, plaintext)


def decrypt_block(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt one 16-byte ciphertext block with a 16-byte key under CLEFIA-128."""
    schedule = key_schedule_128(key)
    return decrypt_block_with_schedule(schedule, ciphertext)


def trace_encrypt_block(key: bytes, plaintext: bytes) -> EncryptionTrace:
    """Encrypt a 16-byte block and return structured round intermediates (non-logging).

    Intended exclusively for unit tests and educational visualization with fixed
    public sample vectors; never call on production secrets and never log outputs.
    """
    schedule = key_schedule_128(key)
    p0, p1, p2, p3 = bytes_to_words128(plaintext)
    wk0, wk1, wk2, wk3 = schedule.whitening_keys
    t0, t1, t2, t3 = p0, p1 ^ wk0, p2, p3 ^ wk1
    after_init = (t0, t1, t2, t3)

    round_traces: list[RoundTrace] = []
    for i in range(ROUNDS_128):
        rk_even = schedule.round_keys[2 * i]
        rk_odd = schedule.round_keys[2 * i + 1]
        f0_out = F0(rk_even, t0)
        f1_out = F1(rk_odd, t2)
        round_traces.append(
            RoundTrace(
                round_number=i + 1,
                input_words=(t0, t1, t2, t3),
                rk_even=rk_even,
                rk_odd=rk_odd,
                f0_out=f0_out,
                f1_out=f1_out,
            )
        )
        t1 ^= f0_out
        t3 ^= f1_out
        t0, t1, t2, t3 = t1, t2, t3, t0

    before_final = (t3, t0, t1, t2)
    c_words = (before_final[0], before_final[1] ^ wk2, before_final[2], before_final[3] ^ wk3)
    return EncryptionTrace(
        after_initial_whitening=after_init,
        rounds=tuple(round_traces),
        before_final_whitening=before_final,
        ciphertext=words128_to_bytes(c_words),
    )
