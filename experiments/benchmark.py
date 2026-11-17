"""Primitive timing benchmark for pure-Python CLEFIA-128.

Benchmarks key_schedule_128, encrypt_block_with_schedule,
decrypt_block_with_schedule, and one-shot encrypt_block/decrypt_block
separately using time.perf_counter_ns().
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import platform
import random
import statistics
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from clefia.cipher import (
    decrypt_block,
    decrypt_block_with_schedule,
    encrypt_block,
    encrypt_block_with_schedule,
)
from clefia.key_schedule import key_schedule_128
from experiments.avalanche import DEFAULT_SEED

DEFAULT_BATCHES = 15
DEFAULT_ITERATIONS = 200
DEFAULT_WARMUP = 250


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = (len(sorted_vals) - 1) * pct
    lo = int(idx)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = idx - lo
    return sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac


def _measure_operation(
    fn: Callable[[], object],
    *,
    warmup: int,
    batches: int,
    iterations: int,
) -> dict[str, Any]:
    for _ in range(warmup):
        fn()

    batch_ns_per_op: list[float] = []
    for _ in range(batches):
        gc.collect()
        was_enabled = gc.isenabled()
        gc.disable()
        try:
            t0 = time.perf_counter_ns()
            for _ in range(iterations):
                fn()
            elapsed = time.perf_counter_ns() - t0
        finally:
            if was_enabled:
                gc.enable()
        batch_ns_per_op.append(elapsed / iterations)

    sorted_vals = sorted(batch_ns_per_op)
    median_ns = statistics.median(sorted_vals)
    mean_ns = statistics.mean(sorted_vals)
    stdev_ns = statistics.stdev(sorted_vals) if len(sorted_vals) > 1 else 0.0
    p95_ns = _percentile(sorted_vals, 0.95)
    ops_per_sec = 1_000_000_000.0 / median_ns if median_ns > 0 else 0.0

    return {
        "median_ns": round(median_ns, 2),
        "mean_ns": round(mean_ns, 2),
        "stdev_ns": round(stdev_ns, 2),
        "p95_ns": round(p95_ns, 2),
        "ops_per_sec": round(ops_per_sec, 2),
        "batch_ns_per_op": [round(v, 2) for v in batch_ns_per_op],
    }


def run_benchmark(
    *,
    seed: int = DEFAULT_SEED,
    batches: int = DEFAULT_BATCHES,
    iterations: int = DEFAULT_ITERATIONS,
    warmup: int = DEFAULT_WARMUP,
) -> dict[str, Any]:
    """Run deterministic CLEFIA-128 primitive benchmarks."""
    rng = random.Random(seed)
    key = rng.randbytes(16)
    plaintext = rng.randbytes(16)
    schedule = key_schedule_128(key)
    ciphertext = encrypt_block_with_schedule(schedule, plaintext)

    operations = {
        "key_schedule_128": _measure_operation(
            lambda: key_schedule_128(key),
            warmup=warmup,
            batches=batches,
            iterations=iterations,
        ),
        "encrypt_block_with_schedule": _measure_operation(
            lambda: encrypt_block_with_schedule(schedule, plaintext),
            warmup=warmup,
            batches=batches,
            iterations=iterations,
        ),
        "decrypt_block_with_schedule": _measure_operation(
            lambda: decrypt_block_with_schedule(schedule, ciphertext),
            warmup=warmup,
            batches=batches,
            iterations=iterations,
        ),
        "encrypt_block_oneshot": _measure_operation(
            lambda: encrypt_block(key, plaintext),
            warmup=warmup,
            batches=batches,
            iterations=iterations,
        ),
        "decrypt_block_oneshot": _measure_operation(
            lambda: decrypt_block(key, ciphertext),
            warmup=warmup,
            batches=batches,
            iterations=iterations,
        ),
    }

    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "seed": seed,
        "warmup": warmup,
        "batches": batches,
        "iterations_per_batch": iterations,
        "environment": {
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
            "processor": platform.processor() or platform.machine(),
            "cpu_count": os.cpu_count(),
        },
        "operations": operations,
    }


def render_benchmark_plot(results: dict[str, Any], path: Path) -> None:
    """Render median and p95 primitive timing bar chart."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    path.parent.mkdir(parents=True, exist_ok=True)
    ops = results["operations"]
    names = list(ops.keys())
    medians_us = [ops[k]["median_ns"] / 1000.0 for k in names]
    p95_us = [ops[k]["p95_ns"] / 1000.0 for k in names]

    x = np.arange(len(names))
    width = 0.36

    fig, ax = plt.subplots(figsize=(9.5, 5.2), dpi=150)
    ax.bar(x - width / 2, medians_us, width, label="Median (mikrodetik/op)", color="#144d8c")
    ax.bar(x + width / 2, p95_us, width, label="Persentil ke-95 (mikrodetik/op)", color="#63a0e6")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=15, ha="right")
    ax.set_ylabel("Waktu (mikrodetik)")
    ax.set_title(
        f"Perbandingan Waktu Eksekusi Primitif CLEFIA-128 (Python Murni)\n"
        f"(batch={results['batches']}, iterasi={results['iterations_per_batch']})"
    )
    ax.legend()
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark CLEFIA-128 pure-Python primitives.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--batches", type=int, default=DEFAULT_BATCHES)
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    parser.add_argument("--results-dir", type=Path, default=Path("experiments/results"))
    parser.add_argument("--plots-dir", type=Path, default=Path("experiments/plots"))
    parser.add_argument("--no-plots", action="store_true")
    args = parser.parse_args()

    args.results_dir.mkdir(parents=True, exist_ok=True)
    results = run_benchmark(
        seed=args.seed,
        batches=args.batches,
        iterations=args.iterations,
        warmup=args.warmup,
    )
    (args.results_dir / "benchmark.json").write_text(
        json.dumps(results, indent=2),
        encoding="utf-8",
    )

    if not args.no_plots:
        render_benchmark_plot(results, args.plots_dir / "benchmark.png")

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
