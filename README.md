# CLEFIA-128: Mathematical Implementation & Indonesian Web Demonstrator (CR-002)

> **Peringatan Akademis Wajib:** **Aplikasi ini hanya untuk demonstrasi akademis algoritma CLEFIA-128. Gunakan data simulasi, bukan nama pengguna atau kata sandi asli. Enkripsi dalam mode CTR tanpa pemeriksaan autentikasi tidak dapat menjamin bahwa data terenkripsi tidak diubah.**

---

## Overview

The project separates its pure cryptographic implementation from web persistence and reproducible diffusion experiments, while presenting a complete **Bahasa Indonesia (`lang="id"`)** web application interface:

1. **Pure-Python Cipher Core (`src/clefia/`):** Implements CLEFIA-128 strictly from Sony's CLEFIA v1.0 specification and [RFC 6114](https://www.rfc-editor.org/rfc/rfc6114.html) without external CLEFIA libraries or web/database imports.
2. **CLEFIA-128-CTR Record Wrapper (`src/clefia/record_crypto.py`):** Wraps variable-length UTF-8 strings (`username`, `password`, and mandatory `profile_note`) with **CLEFIA-128-CTR** using a fresh 96-bit CSPRNG nonce (`secrets.token_bytes(12)`) and 32-bit big-endian counter starting at `1`, with **no HMAC or password hashing** (CR-002 scope).
3. **Indonesian Web Demonstrator (`src/web/`, `app.py`):** FastAPI + Jinja2 + PostgreSQL (`SQLAlchemy 2.x`, `Alembic`, `psycopg`) application storing synthetic `username`, `password`, and mandatory `profile_note` records as CLEFIA-128-CTR ciphertexts in `encrypted_fields`. Account lookup uses **Approach A (bounded O(n) decrypt-and-scan)** over encrypted usernames.
4. **Empirical Experiments (`experiments/`):** Seed-controlled avalanche effect, Strict Avalanche Criterion (SAC), and primitive timing benchmarks operating strictly on the raw 128-bit block cipher, with Bahasa Indonesia visualizations.

---

## Mathematical Specification Summary

Full mathematical traceability (`CR-01` through `CR-12`) is documented in [`docs/mathematics.md`](docs/mathematics.md):

- **Block & Key Size:** 128 bits (16 bytes parsed MSB-first into four 32-bit big-endian words), **18 rounds** for CLEFIA-128.
- **Data Field $\mathrm{GF}(2^8)$:** Arithmetic modulo $p_8(z) = z^8 + z^4 + z^3 + z^2 + 1$ (`0x11D`).
- **Diffusion Matrices:** $4 \times 4$ involutory MDS matrices $M_0$ and $M_1$ over $\mathrm{GF}(2^8)$ with branch number $5$.
- **S-Boxes:** Bijective 8-bit nonlinear permutations $S_0$ and $S_1$ from RFC 6114 Section 4.3 (Tables 1 and 2).
- **Round Functions & Structure:** Four-branch Type-2 Generalized Feistel Network (`GFN_4,18`) with whitening keys $(WK_0, WK_1, WK_2, WK_3)$ and round keys $(RK_0, \dots, RK_{35})$.
- **Key Schedule Constants:** $T_{128}$ (30 values) and $CON_{128}$ (60 values) derived over $\mathrm{GF}(2^{16})$ modulo $p_{16}(z) = z^{16} + z^{15} + z^{13} + z^{11} + z^5 + z^4 + 1$ (`0x1A831`), combined via `GFN_4,12` and 128-bit MSB `DoubleSwap`.

Verified against RFC 6114 Appendix A/B (`K = ffeeddccbbaa99887766554433221100`, `P = 000102030405060708090a0b0c0d0e0f` $\rightarrow$ `C = de2bf2fd9b74aacdf1298555459494fd`, intermediate key `L = 8f89a61b9db9d0f393e65627da0d027e`, all round keys, and rounds 1, 9, and 18).

---

## Design & Trade-Offs (CR-002)

Architecture and threat disclosures are detailed in [`docs/architecture.md`](docs/architecture.md) and [`docs/threat_model.md`](docs/threat_model.md):

- **CLEFIA-128-CTR Only (No HMAC, No Blind Index, No Argon2):** Both synthetic `username` and `password` (plus mandatory `profile_note`) are stored as CLEFIA-128-CTR ciphertexts and 12-byte nonces in `encrypted_fields`. CTR without MAC does **not** detect deliberate ciphertext modification; passwords are encrypted reversibly for educational inspection and must **never** be real passwords.
- **Approach A (Decrypt-and-Scan Lookup):** `canonicalize_username()` applies `Unicode NFKC -> strip() -> casefold()`. Both duplicate detection on `/register` and user lookup on `/login` scan bounded `encrypted_fields` (`field_name = 'username'`) and decrypt via CLEFIA-128-CTR in O(n), constrained by `DEMO_MAX_USERS` (default `100`) and DB advisory/transaction serialization.
- **Web Protections Preserved:** Revocable DB sessions (`user_sessions`), `itsdangerous` signed `HttpOnly` / `SameSite=Lax` cookies (`SESSION_SECRET_KEY` is session infrastructure only), CSRF tokens on `/register`, `/login`, `/profile`, `/change-password`, and `/logout`, `Cache-Control: no-store` on auth views, DB-backed rate limits (`auth_rate_limits`), and localized Indonesian error pages.

---

## Repository Layout

```text
.
├── app.py                        # Vercel / Uvicorn ASGI entrypoint exporting `app`
├── pyproject.toml                # Dependencies, hatchling config, pytest & ruff settings
├── uv.lock                       # Locked reproducible environment
├── vercel.json                   # Vercel function include/exclude rules
├── .vercelignore                 # Excludes local virtualenvs, secrets, and tests from bundles
├── docker-compose.yml            # Local PostgreSQL 16 service
├── .env.example                  # Secret-free environment template
├── alembic/                      # Initial database migration (0001_initial_schema.py)
├── docs/
│   ├── mathematics.md            # RFC 6114 math spec and CR-01..CR-12 traceability
│   ├── architecture.md           # Layer diagram, CTR counter block, binary envelope
│   ├── experiment_protocol.md    # Seeded methodology & interpretation caveats
│   ├── threat_model.md           # Limitations, CTR malleability & prototype threat matrix
│   └── agent_progress.md         # Execution and verification log
├── experiments/
│   ├── avalanche.py              # Plaintext & key 1-bit flip avalanche experiments
│   ├── sac.py                    # Empirical 128x128 Strict Avalanche Criterion matrix
│   ├── benchmark.py              # Pure-Python primitive latency & throughput benchmark
│   ├── results/                  # Generated CSV and JSON summaries (seed=20261115)
│   └── plots/                    # Generated Matplotlib PNG figures (Bahasa Indonesia)
├── scripts/
│   ├── start_local.py            # One-command local SQLite starter
│   ├── verify_postgres.py        # Online PostgreSQL Alembic + CLEFIA-CTR CRUD verifier
│   └── demo_db_tools.py          # Operator opt-in synthetic demo reset helper
├── src/
│   ├── clefia/                   # Pure-Python CLEFIA-128 & ClefiaRecordService (CTR only)
│   └── web/                      # FastAPI app, SQLAlchemy models, auth, Indonesian templates
└── tests/                        # Unit, vector, CTR record, auth, route, and experiment tests
```

---

## Local Setup & Verification

Requires **Python 3.12+** and [`uv`](https://docs.astral.sh/uv/).

### 1. Install Dependencies

```bash
uv sync --frozen --extra dev
# Include Matplotlib/NumPy for regenerating plots under experiments/plots/:
uv sync --extra dev --extra experiments
```

### 2. Configure Local `.env` (PostgreSQL) or PowerShell SQLite Demo

For PostgreSQL via `.env`:

```bash
cp .env.example .env
uv run python -c "import secrets; print('CLEFIA_ENC_KEY_HEX=' + secrets.token_hex(16))"
uv run python -c "import secrets; print('SESSION_SECRET_KEY=' + secrets.token_urlsafe(48))"
```

For quick local SQLite demo in Windows PowerShell (`APP_ENV=test`), run the one-command starter:

```powershell
.\start_local.ps1
# or: uv run python scripts/start_local.py
```

Or configure the session variables manually in PowerShell:

```powershell
$env:APP_ENV = "test"
$env:DATABASE_URL = "sqlite+pysqlite:///$($env:TEMP -replace '\\','/')/clefia_v2_demo.db"
$env:CLEFIA_ENC_KEY_HEX = uv run python -c "import secrets; print(secrets.token_hex(16))"
$env:CLEFIA_KEY_ID = "demo-v2"
$env:SESSION_SECRET_KEY = uv run python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:DEMO_MAX_USERS = "100"
uv run alembic upgrade head
uv run uvicorn app:app --reload
```

### 3. Run Linter and Automated Tests

```bash
uv run ruff check .
uv run pytest -v
```

### 4. Database Migration, Verification & Reset Helper

```bash
uv run alembic upgrade head
uv run alembic upgrade head --sql    # offline PostgreSQL DDL preview
uv run python scripts/verify_postgres.py
```

Operator opt-in database reset (`scripts/demo_db_tools.py` — never runs automatically):

```bash
# Clear synthetic demo rows cleanly when starting fresh
uv run python scripts/demo_db_tools.py reset-demo-db --confirm-reset-demo-db
```

Open `http://127.0.0.1:8000` (health check: `http://127.0.0.1:8000/health`).

---

## Empirical Experiments & Observed Results

Regenerate all CSV, JSON, and Bahasa Indonesia PNG experiment outputs with:

```bash
uv run python -m experiments.sac --seed 20261115 --samples 64
uv run python -m experiments.avalanche --seed 20261115 --samples 64
uv run python -m experiments.benchmark --seed 20261115
```

Baseline results committed in `experiments/results/` (`seed = 20261115`, `samples = 64`):

- **Plaintext 1-bit flip avalanche (`8,192` trials):** Mean Hamming distance `63.9376 / 128` bits (**`49.9513%`**), std `4.4103%`, min `34.375%`, max `66.4062%`.
- **Key 1-bit flip avalanche (`8,192` trials):** Mean Hamming distance `63.8917 / 128` bits (**`49.9154%`**), std `4.4133%`, min `30.4688%`, max `65.625%`.
- **Empirical SAC (`128 x 128 = 16,384` entries, `N = 64`):** Mean `|p_hat - 0.5| = 0.049363`, max `|p_hat - 0.5| = 0.25` (binomial standard error at $p = 0.5$, $N = 64$ is `0.0625`).
- **Pure-Python Primitive Benchmark (`Python 3.13.14` on `Windows-11-10.0.26200-SP0`, `warmup = 250`, `15` batches x `200` ops):**
  - `key_schedule_128`: median `592.56 us/op` (`1687.6` ops/s)
  - `encrypt_block_with_schedule`: median `926.30 us/op` (`1079.56` ops/s)
  - `decrypt_block_with_schedule`: median `954.37 us/op` (`1047.81` ops/s)
  - `encrypt_block_oneshot`: median `1538.93 us/op` (`649.8` ops/s)
  - `decrypt_block_oneshot`: median `1635.85 us/op` (`611.3` ops/s)

> **Statistical Note:** Avalanche averages near `50%` and SAC entries clustered around `0.5` confirm expected empirical diffusion in this implementation, not a formal proof against differential, linear, impossible-differential, or integral cryptanalysis.

---

## Deploying to Vercel + Hosted PostgreSQL

1. Provision a managed PostgreSQL database and run `uv run alembic upgrade head` from a trusted shell.
2. Import this repository into Vercel (uses `app.py`, `pyproject.toml`, `uv.lock`, and `vercel.json`).
3. Set Vercel Environment Variables:
   - `DATABASE_URL` (`postgresql+psycopg://...?sslmode=require`)
   - `CLEFIA_ENC_KEY_HEX` (fresh 32-hex-char 128-bit key)
   - `CLEFIA_KEY_ID` (e.g., `prod-v2`)
   - `SESSION_SECRET_KEY` (random string $\ge 32$ chars)
   - `APP_ENV=production`
   - `DEMO_MAX_USERS=100`
4. Verify live deployment (`GET /health`, `/math`, `/experiments`, register $\rightarrow$ login $\rightarrow$ `/credentials` $\rightarrow$ `/profile` $\rightarrow$ `/change-password` $\rightarrow$ `/logout`).

---

## Demonstration Walkthrough Checklist (Bahasa Indonesia UI)

1. **Peringatan Akademis & Matematis (`/`, `/math`):** Tunjukkan spanduk peringatan akademis berbahasa Indonesia serta perhitungan langsung vektor uji resmi RFC 6114 (`de2bf2fd9b74aacdf1298555459494fd`) dan `Struktur Jaringan Feistel`.
2. **Pendaftaran & Penyimpanan Terenkripsi (`/register`, `/credentials`):** Daftarkan akun simulasi (mis. `mhs_demo_01` / `SandiSimulasi!01`), lalu tunjukkan tabel `Data Terenkripsi` yang hanya memperlihatkan ciphertext heksadesimal & nonce 12-byte untuk `Nama pengguna` dan `Kata sandi` (tanpa kata sandi teks biasa).
3. **Login Pendekatan A (`/login`):** Keluar dan masuk kembali dengan huruf kapital berbeda (mis. `MHS_DEMO_01`) untuk mendemonstrasikan kanonikalisasi `NFKC + strip + casefold` dan pemindaian dekripsi nama pengguna satu per satu.
4. **Catatan Profil Wajib (`/dashboard`, `/profile`):** Simpan catatan panjang berbahasa Indonesia (> 16 byte), lihat hasil dekripsi khusus pemilik, dan buktikan pengguna lain tidak dapat membacanya.
5. **Ubah Kata Sandi (`/change-password`):** Perbarui kata sandi simulasi dan tunjukkan nonce berubah sementara kata sandi lama ditolak.
6. **Eksperimen & Batasan Mode CTR (`/experiments`):** Tunjukkan grafik Efek Avalanche, SAC, dan Waktu Eksekusi berlabel Bahasa Indonesia, serta jelaskan keterbatasan mode CTR tanpa MAC, kata sandi reversibel, dan kompleksitas pemindaian O(n).
