"""Empirical Strict Avalanche Criterion (SAC) experiment for CLEFIA-128.

Computes the 128 x 128 flip probability matrix p_hat_{ij} for plaintext bit
flips across N deterministic (key, plaintext) pairs and renders a heatmap.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
from datetime import UTC, datetime
from pathlib import Path

from clefia.cipher import encrypt_block_with_schedule
from clefia.key_schedule import key_schedule_128
from experiments.avalanche import BLOCK_BITS, DEFAULT_SAMPLES, DEFAULT_SEED, flip_bit_128


def compute_sac_matrix(
    *,
    seed: int = DEFAULT_SEED,
    samples: int = DEFAULT_SAMPLES,
) -> tuple[list[list[int]], list[list[float]]]:
    """Estimate 128x128 empirical flip counts and probabilities p_hat[i][j]."""
    if samples < 1:
        raise ValueError("samples must be >= 1")
    rng = random.Random(seed)
    pairs = [(rng.randbytes(16), rng.randbytes(16)) for _ in range(samples)]

    counts: list[list[int]] = [[0] * BLOCK_BITS for _ in range(BLOCK_BITS)]

    for key, plaintext in pairs:
        ks = key_schedule_128(key)
        base_int = int.from_bytes(encrypt_block_with_schedule(ks, plaintext), "big")
        for input_bit in range(BLOCK_BITS):
            flipped_pt = flip_bit_128(plaintext, input_bit)
            ct_int = int.from_bytes(encrypt_block_with_schedule(ks, flipped_pt), "big")
            diff = base_int ^ ct_int
            row = counts[input_bit]
            for out_bit in range(BLOCK_BITS):
                if (diff >> (127 - out_bit)) & 1:
                    row[out_bit] += 1

    probs = [[c / samples for c in row] for row in counts]
    return counts, probs


def write_sac_csv(
    counts: list[list[int]],
    probs: list[list[float]],
    path: Path,
    *,
    seed: int,
    samples: int,
) -> None:
    """Save tidy 128x128 SAC probability matrix to CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["seed", "samples", "input_bit", "output_bit", "flip_count", "flip_prob"])
        for i in range(BLOCK_BITS):
            for j in range(BLOCK_BITS):
                writer.writerow([seed, samples, i, j, counts[i][j], f"{probs[i][j]:.6f}"])


def summarize_sac(probs: list[list[float]], *, samples: int) -> dict[str, float | int]:
    """Summarize SAC deviations from 0.5 and theoretical binomial sampling SE."""
    devs = [abs(p - 0.5) for row in probs for p in row]
    mean_abs_dev = sum(devs) / len(devs)
    max_abs_dev = max(devs)
    binomial_se = 0.5 / math.sqrt(samples)
    return {
        "samples": samples,
        "matrix_entries": len(devs),
        "mean_abs_deviation_from_0_5": round(mean_abs_dev, 6),
        "max_abs_deviation_from_0_5": round(max_abs_dev, 6),
        "binomial_standard_error_at_0_5": round(binomial_se, 6),
    }


def render_sac_heatmap(
    probs: list[list[float]],
    path: Path,
    *,
    seed: int,
    samples: int,
) -> None:
    """Render 128x128 SAC probability heatmap."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    path.parent.mkdir(parents=True, exist_ok=True)
    arr = np.array(probs, dtype=float)

    fig, ax = plt.subplots(figsize=(7.6, 6.4), dpi=150)
    im = ax.imshow(arr, cmap="coolwarm", vmin=0.0, vmax=1.0, aspect="auto")
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("Probabilitas Perubahan Bit Empiris p_hat(i, j)")
    ax.set_title(
        f"Peta Panas Kriteria Avalanche Ketat (SAC) CLEFIA-128\n"
        f"(seed={seed}, N={samples})"
    )
    ax.set_xlabel("Bit Keluaran j (0 = MSB, 127 = LSB)")
    ax.set_ylabel("Bit Plaintext Masukan yang Diubah i (0 = MSB, 127 = LSB)")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CLEFIA-128 empirical SAC matrix experiment.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    parser.add_argument("--results-dir", type=Path, default=Path("experiments/results"))
    parser.add_argument("--plots-dir", type=Path, default=Path("experiments/plots"))
    parser.add_argument("--no-plots", action="store_true")
    args = parser.parse_args()

    counts, probs = compute_sac_matrix(seed=args.seed, samples=args.samples)
    write_sac_csv(
        counts,
        probs,
        args.results_dir / "sac_matrix.csv",
        seed=args.seed,
        samples=args.samples,
    )
    summary = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "seed": args.seed,
        **summarize_sac(probs, samples=args.samples),
    }
    (args.results_dir / "sac_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    if not args.no_plots:
        render_sac_heatmap(
            probs,
            args.plots_dir / "sac_heatmap.png",
            seed=args.seed,
            samples=args.samples,
        )

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
