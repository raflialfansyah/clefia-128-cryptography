"""CLEFIA 4-branch Generalized Feistel Network (GFN_{4,r}) and inverse (GFNINV_{4,r}).

References:
    - RFC 6114, Section 4.1 (GFN_{d,r} and GFNINV_{4,r}).
"""

from __future__ import annotations

from collections.abc import Sequence

from clefia.field import _require_uint
from clefia.functions import F0, F1


def _validate_gfn4_inputs(
    round_keys: Sequence[int],
    state: Sequence[int],
    rounds: int,
) -> tuple[list[int], int, int, int, int]:
    """Validate round count, round keys (2*r 32-bit words), and 4-word state."""
    if isinstance(rounds, bool) or not isinstance(rounds, int) or rounds < 1:
        raise ValueError(f"rounds must be an integer >= 1, got {rounds!r}")
    expected_rk_len = 2 * rounds
    if len(round_keys) != expected_rk_len:
        raise ValueError(
            f"GFN_{{4,{rounds}}} requires {expected_rk_len} round keys, got {len(round_keys)}"
        )
    if len(state) != 4:
        raise ValueError(f"GFN_{{4,{rounds}}} requires 4 32-bit state words, got {len(state)}")
    rks = [_require_uint(rk, 32, f"round_keys[{i}]") for i, rk in enumerate(round_keys)]
    t0 = _require_uint(state[0], 32, "state[0]")
    t1 = _require_uint(state[1], 32, "state[1]")
    t2 = _require_uint(state[2], 32, "state[2]")
    t3 = _require_uint(state[3], 32, "state[3]")
    return rks, t0, t1, t2, t3


def gfn4(
    round_keys: Sequence[int],
    state: Sequence[int],
    rounds: int,
) -> tuple[int, int, int, int]:
    """Evaluate forward 4-branch r-round Generalized Feistel Network GFN_{4,r}.

    Matches RFC 6114 Section 4.1:
        For i = 0 .. r-1:
            T1 ^= F0(RK_{2i}, T0)
            T3 ^= F1(RK_{2i+1}, T2)
            T0, T1, T2, T3 <- T1, T2, T3, T0
        Final output adjustment:
            return T3, T0, T1, T2
    """
    rks, t0, t1, t2, t3 = _validate_gfn4_inputs(round_keys, state, rounds)
    for i in range(rounds):
        t1 ^= F0(rks[2 * i], t0)
        t3 ^= F1(rks[2 * i + 1], t2)
        t0, t1, t2, t3 = t1, t2, t3, t0
    return (t3, t0, t1, t2)


def gfn4_inv(
    round_keys: Sequence[int],
    state: Sequence[int],
    rounds: int,
) -> tuple[int, int, int, int]:
    """Evaluate inverse 4-branch r-round Generalized Feistel Network GFNINV_{4,r}.

    Matches RFC 6114 Section 4.1:
        For i = 0 .. r-1:
            T1 ^= F0(RK_{2(r-i)-2}, T0)
            T3 ^= F1(RK_{2(r-i)-1}, T2)
            T0, T1, T2, T3 <- T3, T0, T1, T2
        Final output adjustment:
            return T1, T2, T3, T0
    """
    rks, t0, t1, t2, t3 = _validate_gfn4_inputs(round_keys, state, rounds)
    for i in range(rounds):
        idx = 2 * (rounds - i)
        t1 ^= F0(rks[idx - 2], t0)
        t3 ^= F1(rks[idx - 1], t2)
        t0, t1, t2, t3 = t3, t0, t1, t2
    return (t1, t2, t3, t0)
