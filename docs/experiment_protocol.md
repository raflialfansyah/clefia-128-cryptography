# Experiment Protocol and Reproducibility Notes

All empirical experiments operate exclusively on the **raw 128-bit CLEFIA-128 block primitive** (`src/clefia/cipher.py` and `src/clefia/key_schedule.py`), never on the randomized `RecordCryptoService` wrapper where per-message random nonces would confound bit-flip measurements.

---

## 1. Bit-Indexing Convention

Input blocks and keys are 16 bytes ($128$ bits). Bit index $i \in \{0, \dots, 127\}$ follows **MSB-first** ordering:
- Byte index: $\lfloor i / 8 \rfloor$
- Bit mask within byte: $1 \ll (7 - (i \bmod 8))$

Thus indices $0\dots 31$ correspond to branch word $P_0$, $32\dots 63$ to $P_1$, $64\dots 95$ to $P_2$, and $96\dots 127$ to $P_3$.

---

## 2. Avalanche Effect (`experiments/avalanche.py`)

- **Seed:** Configurable PRNG seed via `--seed` (baseline default: `20261115`).
- **Sample count:** Configurable independent `(K, P)` pairs via `--samples` (baseline default: `64`).
- **Plaintext-flip trials:** For each $(K_s, P_s)$ and each bit $i \in \{0,\dots,127\}$ ($64 \times 128 = 8{,}192$ trials):
  $$A^{\mathrm{pt}}_i(K_s, P_s) = \frac{\mathrm{HD}(E_{K_s}(P_s),\; E_{K_s}(P_s \oplus e_i))}{128} \times 100\%.$$
- **Key-flip trials:** Using the same 64 pairs, flip one bit $i$ of $K_s$ ($8{,}192$ trials):
  $$A^{\mathrm{key}}_i(K_s, P_s) = \frac{\mathrm{HD}(E_{K_s}(P_s),\; E_{K_s \oplus e_i}(P_s))}{128} \times 100\%.$$
- **Outputs:**
  - `experiments/results/avalanche_plaintext.csv`
  - `experiments/results/avalanche_key.csv`
  - `experiments/results/avalanche_summary.json`
  - `experiments/plots/avalanche_histogram.png`
  - `experiments/plots/avalanche_positions.png`

---

## 3. Empirical Strict Avalanche Criterion (`experiments/sac.py`)

- For each input bit $i \in \{0,\dots,127\}$ and output bit $j \in \{0,\dots,127\}$, estimate the output bit-flip probability across $N$ baseline pairs:
  $$\widehat{p}_{ij} = \frac{1}{N} \sum_{s=1}^{N} \mathbf{1}\!\left[E_{K_s}(P_s)_j \neq E_{K_s}(P_s \oplus e_i)_j\right].$$
- **Sampling uncertainty:** For $N = 64$ and true $p = 0.5$, the binomial standard error is $\sigma = \frac{0.5}{\sqrt{64}} = 0.0625$ ($\approx 6.25$ percentage points), with expected $| \widehat{p}_{ij} - 0.5 | \approx \sqrt{\frac{2}{\pi}} \cdot 0.0625 \approx 0.0499$.
- **Outputs:**
  - `experiments/results/sac_matrix.csv` (16,384 rows)
  - `experiments/results/sac_summary.json`
  - `experiments/plots/sac_heatmap.png`

---

## 4. Primitive Timing Benchmark (`experiments/benchmark.py`)

- Measures pure-Python primitive costs separately using `time.perf_counter_ns()` after warm-up passes:
  1. `key_schedule_128`
  2. `encrypt_block_with_schedule` (18 rounds, pre-expanded key)
  3. `decrypt_block_with_schedule` (18 inverse rounds, pre-expanded key)
  4. `encrypt_block_oneshot` (key schedule + 1 block encryption)
  5. `decrypt_block_oneshot` (key schedule + 1 block decryption)
- Reports median, mean, stdev, and p95 in `ns/op` alongside `ops/s` and runtime environment metadata (Python version, OS, processor, CPU count, seed, warm-up, batch/iteration counts).
- **Outputs:**
  - `experiments/results/benchmark.json`
  - `experiments/plots/benchmark.png`

---

## 5. Interpretation Boundaries

Empirical avalanche averages near $50\%$ and SAC values near $0.5$ demonstrate strong statistical diffusion across the implemented permutation and are useful sanity indicators alongside official RFC 6114 test vectors. They do **not** constitute a formal mathematical proof of resistance against differential, linear, impossible-differential, or integral cryptanalysis.
