"""Repeatability and sanity tests for offline experiment scripts (T-011)."""

from __future__ import annotations

from pathlib import Path

from experiments.avalanche import flip_bit_128, hamming_distance_128, run_avalanche_experiment
from experiments.benchmark import run_benchmark
from experiments.sac import compute_sac_matrix


def test_avalanche_bit_flip_and_repeatability_t011() -> None:
    """T-011: Identical seed/samples produce byte-for-byte identical avalanche results."""
    flipped = flip_bit_128(b"\x00" * 16, 0)
    assert flipped == b"\x80" + b"\x00" * 15
    assert hamming_distance_128(b"\x00" * 16, flipped) == 1

    pt_a, key_a = run_avalanche_experiment(seed=20261115, samples=2)
    pt_b, key_b = run_avalanche_experiment(seed=20261115, samples=2)
    assert pt_a == pt_b
    assert key_a == key_b
    assert len(pt_a) == 256
    assert len(key_a) == 256


def test_sac_repeatability_and_matrix_shape() -> None:
    """SAC produces reproducible 128x128 counts and probabilities in [0.0, 1.0]."""
    counts_a, probs_a = compute_sac_matrix(seed=20261115, samples=2)
    counts_b, probs_b = compute_sac_matrix(seed=20261115, samples=2)
    assert counts_a == counts_b
    assert probs_a == probs_b
    assert len(probs_a) == 128
    assert all(len(row) == 128 for row in probs_a)
    assert all(0.0 <= p <= 1.0 for row in probs_a for p in row)


def test_benchmark_structure_and_non_zero_timings() -> None:
    """Benchmark captures environment metadata and positive timings."""
    res = run_benchmark(seed=20261115, batches=2, iterations=5, warmup=1)
    assert res["seed"] == 20261115
    assert "python_version" in res["environment"]
    for op_name in (
        "key_schedule_128",
        "encrypt_block_with_schedule",
        "decrypt_block_with_schedule",
    ):
        assert res["operations"][op_name]["median_ns"] > 0
        assert res["operations"][op_name]["ops_per_sec"] > 0


def test_experiments_route_renders_committed_results_when_present(tmp_path: Path) -> None:
    """Smoke check that /experiments parses generated results cleanly."""
    from web.routes import _summarize_avalanche_csv

    csv_file = tmp_path / "avalanche.csv"
    csv_file.write_text(
        "seed,experiment,pair_index,bit_index,hamming_distance,avalanche_pct\n"
        "20261115,plaintext_flip,0,0,64,50.000000\n",
        encoding="utf-8",
    )
    summary = _summarize_avalanche_csv(csv_file)
    assert summary is not None
    assert summary["seed"] == "20261115"
    assert summary["mean_pct"] == "50.00"
