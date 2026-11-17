"""Reproducible plaintext and key avalanche experiments for CLEFIA-128.

Operates strictly on the raw 128-bit CLEFIA block primitive (never the randomized
record-encryption wrapper). Bit index i in 0..127 follows MSB-first convention
(byte i // 8, bit mask 1 << (7 - (i % 8))).
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from clefia.cipher import encrypt_block_with_schedule
from clefia.key_schedule import key_schedule_128

DEFAULT_SEED = 20261115
DEFAULT_SAMPLES = 64
BLOCK_BITS = 128


@dataclass(frozen=True, slots=True)
class AvalancheTrial:
    """Single bit-flip avalanche observation."""

    seed: int
    experiment: str
    pair_index: int
    bit_index: int
    hamming_distance: int
    avalanche_pct: float


def flip_bit_128(data: bytes, bit_index: int) -> bytes:
    """Flip one bit (0 = MSB of byte 0, 127 = LSB of byte 15) in a 16-byte block/key."""
    if len(data) != 16:
        raise ValueError(f"Expected 16 bytes, got {len(data)}")
    if bit_index < 0 or bit_index >= BLOCK_BITS:
        raise ValueError(f"bit_index must be in 0..127, got {bit_index}")
    buf = bytearray(data)
    buf[bit_index // 8] ^= 1 << (7 - (bit_index % 8))
    return bytes(buf)


def hamming_distance_128(a: bytes, b: bytes) -> int:
    """Return bit-level Hamming distance between two 16-byte blocks."""
    diff = int.from_bytes(a, "big") ^ int.from_bytes(b, "big")
    return diff.bit_count()


def run_avalanche_experiment(
    *,
    seed: int = DEFAULT_SEED,
    samples: int = DEFAULT_SAMPLES,
) -> tuple[list[AvalancheTrial], list[AvalancheTrial]]:
    """Run deterministic plaintext-flip and key-flip avalanche experiments."""
    if samples < 1:
        raise ValueError("samples must be >= 1")
    rng = random.Random(seed)
    pairs = [(rng.randbytes(16), rng.randbytes(16)) for _ in range(samples)]

    pt_trials: list[AvalancheTrial] = []
    key_trials: list[AvalancheTrial] = []

    for pair_idx, (key, plaintext) in enumerate(pairs):
        base_schedule = key_schedule_128(key)
        base_ct = encrypt_block_with_schedule(base_schedule, plaintext)

        for bit_idx in range(BLOCK_BITS):
            flipped_pt = flip_bit_128(plaintext, bit_idx)
            ct_pt_flip = encrypt_block_with_schedule(base_schedule, flipped_pt)
            hd_pt = hamming_distance_128(base_ct, ct_pt_flip)
            pt_trials.append(
                AvalancheTrial(
                    seed=seed,
                    experiment="plaintext_flip",
                    pair_index=pair_idx,
                    bit_index=bit_idx,
                    hamming_distance=hd_pt,
                    avalanche_pct=(hd_pt / BLOCK_BITS) * 100.0,
                )
            )

            flipped_key = flip_bit_128(key, bit_idx)
            flipped_schedule = key_schedule_128(flipped_key)
            ct_key_flip = encrypt_block_with_schedule(flipped_schedule, plaintext)
            hd_key = hamming_distance_128(base_ct, ct_key_flip)
            key_trials.append(
                AvalancheTrial(
                    seed=seed,
                    experiment="key_flip",
                    pair_index=pair_idx,
                    bit_index=bit_idx,
                    hamming_distance=hd_key,
                    avalanche_pct=(hd_key / BLOCK_BITS) * 100.0,
                )
            )

    return pt_trials, key_trials


def summarize_trials(trials: list[AvalancheTrial]) -> dict[str, float | int]:
    """Compute aggregate statistics over avalanche trials."""
    n = len(trials)
    pcts = [t.avalanche_pct for t in trials]
    hds = [t.hamming_distance for t in trials]
    mean_pct = sum(pcts) / n
    mean_hd = sum(hds) / n
    var_pct = sum((p - mean_pct) ** 2 for p in pcts) / max(1, n - 1)
    return {
        "trials": n,
        "mean_hamming_distance": round(mean_hd, 4),
        "mean_avalanche_pct": round(mean_pct, 4),
        "std_avalanche_pct": round(math.sqrt(var_pct), 4),
        "min_avalanche_pct": round(min(pcts), 4),
        "max_avalanche_pct": round(max(pcts), 4),
    }


def write_trials_csv(trials: list[AvalancheTrial], path: Path) -> None:
    """Persist per-trial avalanche measurements to CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "seed",
                "experiment",
                "pair_index",
                "bit_index",
                "hamming_distance",
                "avalanche_pct",
            ]
        )
        for t in trials:
            writer.writerow(
                [
                    t.seed,
                    t.experiment,
                    t.pair_index,
                    t.bit_index,
                    t.hamming_distance,
                    f"{t.avalanche_pct:.6f}",
                ]
            )


def render_avalanche_plots(
    pt_trials: list[AvalancheTrial],
    key_trials: list[AvalancheTrial],
    plots_dir: Path,
    *,
    seed: int,
    samples: int,
) -> None:
    """Render Hamming distance histogram and per-bit-position avalanche plots."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plots_dir.mkdir(parents=True, exist_ok=True)

    pt_hds = [t.hamming_distance for t in pt_trials]
    key_hds = [t.hamming_distance for t in key_trials]

    # 1. Histogram distribusi jarak Hamming keluaran
    fig, ax = plt.subplots(figsize=(8.8, 5.0), dpi=150)
    bins = [x - 0.5 for x in range(32, 97)]
    ax.hist(pt_hds, bins=bins, alpha=0.6, label="Perubahan 1 bit plaintext", color="#144d8c")
    ax.hist(key_hds, bins=bins, alpha=0.55, label="Perubahan 1 bit kunci", color="#d97706")
    ax.axvline(64.0, color="#16202a", linestyle="--", linewidth=1.2, label="Ideal 50% (64 bit)")
    ax.set_title(
        f"Distribusi Jarak Hamming Efek Avalanche CLEFIA-128\n"
        f"(seed={seed}, N={samples} pasangan)"
    )
    ax.set_xlabel("Jarak Hamming Keluaran (bit dari 128)")
    ax.set_ylabel("Frekuensi Percobaan")
    ax.legend()
    ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(plots_dir / "avalanche_histogram.png")
    plt.close(fig)

    # 2. Rata-rata persentase avalanche berdasarkan posisi bit masukan (0..127)
    pt_by_bit = [
        sum(t.avalanche_pct for t in pt_trials if t.bit_index == b) / samples
        for b in range(BLOCK_BITS)
    ]
    key_by_bit = [
        sum(t.avalanche_pct for t in key_trials if t.bit_index == b) / samples
        for b in range(BLOCK_BITS)
    ]

    fig, ax = plt.subplots(figsize=(9.5, 5.0), dpi=150)
    positions = list(range(BLOCK_BITS))
    ax.plot(
        positions,
        pt_by_bit,
        label="Rata-rata ubah plaintext (%)",
        color="#144d8c",
        linewidth=1.3,
    )
    ax.plot(
        positions,
        key_by_bit,
        label="Rata-rata ubah kunci (%)",
        color="#d97706",
        linewidth=1.1,
        alpha=0.85,
    )
    ax.axhline(50.0, color="#16202a", linestyle="--", linewidth=1.1, label="Referensi 50%")
    ax.set_title(
        f"Efek Avalanche Rata-rata per Posisi Bit CLEFIA-128\n"
        f"(seed={seed}, N={samples} pasangan)"
    )
    ax.set_xlabel("Posisi Bit Masukan yang Diubah (0 = MSB, 127 = LSB)")
    ax.set_ylabel("Rata-rata Perubahan Bit Keluaran (%)")
    ax.set_ylim(35.0, 65.0)
    ax.legend()
    ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(plots_dir / "avalanche_positions.png")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CLEFIA-128 avalanche experiments.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    parser.add_argument("--results-dir", type=Path, default=Path("experiments/results"))
    parser.add_argument("--plots-dir", type=Path, default=Path("experiments/plots"))
    parser.add_argument("--no-plots", action="store_true")
    args = parser.parse_args()

    pt_trials, key_trials = run_avalanche_experiment(seed=args.seed, samples=args.samples)
    write_trials_csv(pt_trials, args.results_dir / "avalanche_plaintext.csv")
    write_trials_csv(key_trials, args.results_dir / "avalanche_key.csv")

    summary = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "seed": args.seed,
        "samples": args.samples,
        "plaintext_flip": summarize_trials(pt_trials),
        "key_flip": summarize_trials(key_trials),
    }
    (args.results_dir / "avalanche_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    if not args.no_plots:
        render_avalanche_plots(
            pt_trials,
            key_trials,
            args.plots_dir,
            seed=args.seed,
            samples=args.samples,
        )

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
