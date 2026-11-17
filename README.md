# CLEFIA-128: Implementasi Matematis & Demonstrasi Web Berbahasa Indonesia

> **Peringatan Akademis Wajib:** **Aplikasi ini hanya untuk demonstrasi akademis algoritma CLEFIA-128. Gunakan data simulasi, bukan nama pengguna atau kata sandi asli. Enkripsi dalam mode CTR tanpa pemeriksaan autentikasi tidak dapat menjamin bahwa data terenkripsi tidak diubah.**

---

## Ringkasan Proyek

Proyek ini memisahkan implementasi matematis cipher blok dari lapisan persistensi web dan eksperimen difusi yang dapat direproduksi, sekaligus menyajikan antarmuka web berbahasa Indonesia (`lang="id"`):

1. **Inti Cipher Python Murni (`src/clefia/`):** Mengimplementasikan CLEFIA-128 secara ketat mengikuti spesifikasi resmi Sony CLEFIA v1.0 dan [RFC 6114](https://www.rfc-editor.org/rfc/rfc6114.html) tanpa pustaka CLEFIA eksternal maupun ketergantungan pada framework web atau basis data.
2. **Pembungkus Rekaman CLEFIA-128-CTR (`src/clefia/record_crypto.py`):** Mengenkripsi string UTF-8 dengan panjang bervariasi (`username`, `password`, dan `profile_note` wajib) menggunakan **CLEFIA-128 mode CTR**, nonce CSPRNG 96-bit yang baru (`secrets.token_bytes(12)`), dan pencacah (*counter*) big-endian 32-bit mulai dari `1`, tanpa tag HMAC atau hashing kata sandi.
3. **Aplikasi Web Demonstrator (`src/web/`, `app.py`):** Aplikasi FastAPI + Jinja2 + PostgreSQL (`SQLAlchemy 2.x`, `Alembic`, `psycopg`) yang menyimpan `username`, `password`, dan `profile_note` simulasi dalam bentuk ciphertext CLEFIA-128-CTR pada tabel `encrypted_fields`. Pencarian akun saat pendaftaran maupun login menggunakan **Pendekatan A (*decrypt-and-scan* terbatas O(n))** terhadap nama pengguna terenkripsi.
4. **Eksperimen Empiris (`experiments/`):** Pengukuran efek avalanche, *Strict Avalanche Criterion* (SAC), dan benchmark waktu eksekusi primitif Python murni menggunakan seed deterministik, disertai grafik berlabel Bahasa Indonesia.

---

## Ringkasan Spesifikasi Matematis

Ketertelusuran matematis lengkap (`CR-01` sampai `CR-12`) terdokumentasi di [`docs/mathematics.md`](docs/mathematics.md):

- **Ukuran Blok & Kunci:** 128 bit (16 byte dibaca MSB-pertama menjadi empat kata big-endian 32-bit), **18 putaran** untuk CLEFIA-128.
- **Medan Hingga Data $\mathrm{GF}(2^8)$:** Aritmetika polinomial modulo $p_8(z) = z^8 + z^4 + z^3 + z^2 + 1$ (`0x11D`).
- **Matriks Difusi:** Dua matriks MDS involutif $4 \times 4$, yaitu $M_0$ dan $M_1$, pada $\mathrm{GF}(2^8)$ dengan *branch number* $5$.
- **S-Box:** Permutasi non-linear bijektif 8-bit $S_0$ dan $S_1$ dari RFC 6114 Bagian 4.3 (Tabel 1 dan 2).
- **Fungsi Putaran & Struktur:** Jaringan Feistel tergeneralisasi empat cabang tipe-2 ($\mathrm{GFN}_{4,18}$) dengan kunci pemutihan $(WK_0, WK_1, WK_2, WK_3)$ serta 36 kunci putaran $(RK_0, \dots, RK_{35})$.
- **Konstanta Penjadwalan Kunci:** $T_{128}$ (30 nilai) dan $CON_{128}$ (60 nilai) diturunkan pada $\mathrm{GF}(2^{16})$ modulo $p_{16}(z) = z^{16} + z^{15} + z^{13} + z^{11} + z^5 + z^4 + 1$ (`0x1A831`), digabungkan melalui $\mathrm{GFN}_{4,12}$ dan permutasi bit MSB 128-bit `DoubleSwap`.

Terverifikasi terhadap vektor uji resmi RFC 6114 Lampiran A/B (`K = ffeeddccbbaa99887766554433221100`, `P = 000102030405060708090a0b0c0d0e0f` $\rightarrow$ `C = de2bf2fd9b74aacdf1298555459494fd`, kunci antara `L = 8f89a61b9db9d0f393e65627da0d027e`, seluruh kunci putaran, serta putaran 1, 9, dan 18).

---

## Desain & Keterbatasan Keamanan

Arsitektur sistem dan batasan keamanan dijelaskan lengkap pada [`docs/architecture.md`](docs/architecture.md) dan [`docs/threat_model.md`](docs/threat_model.md):

- **Hanya CLEFIA-128-CTR (Tanpa HMAC, Tanpa *Blind Index*, Tanpa Argon2):** Baik `username`, `password` simulasi, maupun `profile_note` disimpan sebagai ciphertext CLEFIA-128-CTR beserta nonce 12-byte pada `encrypted_fields`. Mode CTR tanpa MAC **tidak** mendeteksi manipulasi ciphertext secara kriptografis, dan kata sandi terenkripsi bersifat reversibel dengan kunci server sehingga **tidak boleh** memakai kata sandi asli.
- **Pendekatan A (*Decrypt-and-Scan*):** `canonicalize_username()` menerapkan `Unicode NFKC -> strip() -> casefold()`. Pemeriksaan duplikasi pada `/register` maupun pencarian akun pada `/login` memindai baris `encrypted_fields` (`field_name = 'username'`) secara terbatas O(n), dibatasi oleh `DEMO_MAX_USERS` (bawaan `100`) serta penguncian transaksi/advisory saat pendaftaran.
- **Perlindungan Aplikasi Web yang Dipertahankan:** Sesi basis data yang dapat dicabut (`user_sessions`), cookie bertanda tangan `itsdangerous` dengan flag `HttpOnly` dan `SameSite=Lax` (`SESSION_SECRET_KEY` hanya untuk infrastruktur sesi), token CSRF pada formulir `/register`, `/login`, `/profile`, `/change-password`, dan `/logout`, header `Cache-Control: no-store`, pembatasan percobaan login (`auth_rate_limits`), serta halaman galat berbahasa Indonesia.

---

## Struktur Repositori

```text
.
├── app.py                        # Titik masuk ASGI Vercel / Uvicorn yang mengekspor `app`
├── pyproject.toml                # Dependensi, konfigurasi hatchling, pytest & ruff
├── uv.lock                       # Lockfile lingkungan Python yang terverifikasi
├── vercel.json                   # Aturan bundel fungsi Vercel
├── .vercelignore                 # Mengecualikan virtualenv lokal, rahasia, dan berkas uji
├── docker-compose.yml            # Layanan PostgreSQL 16 lokal (opsional)
├── .env.example                  # Templat variabel lingkungan tanpa kunci rahasia
├── alembic/                      # Migrasi awal basis data (0001_initial_schema.py)
├── docs/
│   ├── mathematics.md            # Spesifikasi matematika RFC 6114 & ketertelusuran CR-01..CR-12
│   ├── architecture.md           # Diagram arsitektur, format blok CTR, format biner
│   ├── experiment_protocol.md    # Metodologi seed eksperimen & batasan interpretasi
│   ├── threat_model.md           # Matriks ancaman, maleabilitas CTR & keterbatasan prototipe
│   └── agent_progress.md         # Catatan eksekusi & hasil verifikasi
├── experiments/
│   ├── avalanche.py              # Eksperimen efek avalanche perubahan 1 bit plaintext & kunci
│   ├── sac.py                    # Eksperimen matriks 128x128 Strict Avalanche Criterion (SAC)
│   ├── benchmark.py              # Benchmark latensi & throughput primitif Python murni
│   ├── results/                  # Ringkasan hasil CSV dan JSON (seed=20261115)
│   └── plots/                    # Gambar grafik PNG Matplotlib (berbahasa Indonesia)
├── scripts/
│   ├── start_local.py            # Skrip pemulai satu perintah untuk demo SQLite lokal
│   ├── verify_postgres.py        # Skrip verifikasi Alembic + CRUD CLEFIA-CTR PostgreSQL
│   └── demo_db_tools.py          # Alat bantu operator untuk reset data simulasi (opt-in)
├── start_local.ps1               # Peluncur satu perintah PowerShell Windows
├── src/
│   ├── clefia/                   # Inti CLEFIA-128 Python murni & ClefiaRecordService (CTR)
│   └── web/                      # Aplikasi FastAPI, model SQLAlchemy, autentikasi, templat HTML
└── tests/                        # Pengujian unit, vektor RFC, CTR, autentikasi, rute & eksperimen
```

---

## Instalasi & Cara Menjalankan Secara Lokal

Membutuhkan **Python 3.12+** dan [`uv`](https://docs.astral.sh/uv/).

### 1. Pasang Dependensi

```bash
uv sync --frozen --extra dev
# Tambahkan ekstra experiments jika ingin membuat ulang grafik di experiments/plots/:
uv sync --extra dev --extra experiments
```

### 2. Jalankan Demo SQLite Lokal (Satu Perintah di PowerShell Windows)

Untuk demonstrasi cepat menggunakan SQLite lokal (`APP_ENV=test`), cukup jalankan:

```powershell
.\start_local.ps1
# atau lintas platform:
uv run python scripts/start_local.py
```

Skrip tersebut membuat/menggunakan konfigurasi lokal persisten di direktori `%TEMP%` (tanpa menaruh kunci rahasia ke dalam repositori), menjalankan `alembic upgrade head`, lalu menyalakan `uvicorn app:app --reload` di **`http://127.0.0.1:8000`**.

Atau jika ingin menggunakan PostgreSQL melalui berkas `.env`:

```bash
cp .env.example .env
uv run python -c "import secrets; print('CLEFIA_ENC_KEY_HEX=' + secrets.token_hex(16))"
uv run python -c "import secrets; print('SESSION_SECRET_KEY=' + secrets.token_urlsafe(48))"
```

Lalu jalankan migrasi dan server web:

```bash
uv run alembic upgrade head
uv run uvicorn app:app --reload
```

### 3. Jalankan Linter dan Pengujian Otomatis

```bash
uv run ruff check .
uv run pytest -v
```

### 4. Migrasi Basis Data, Verifikasi PostgreSQL & Reset Data Simulasi

```bash
uv run alembic upgrade head
uv run alembic upgrade head --sql    # pratinjau DDL PostgreSQL tanpa koneksi server
uv run python scripts/verify_postgres.py
```

Reset data simulasi secara eksplisit oleh operator (`scripts/demo_db_tools.py`, tidak pernah berjalan otomatis):

```bash
uv run python scripts/demo_db_tools.py reset-demo-db --confirm-reset-demo-db
```

Buka **`http://127.0.0.1:8000`** di peramban (pemeriksaan kesehatan layanan: `http://127.0.0.1:8000/health`).

---

## Eksperimen Empiris & Hasil Teramati

Hasilkan ulang seluruh keluaran CSV, JSON, dan grafik PNG berbahasa Indonesia dengan perintah:

```bash
uv run python -m experiments.sac --seed 20261115 --samples 64
uv run python -m experiments.avalanche --seed 20261115 --samples 64
uv run python -m experiments.benchmark --seed 20261115
```

Ringkasan hasil bawaan pada `experiments/results/` (`seed = 20261115`, `samples = 64`):

- **Efek Avalanche perubahan 1 bit plaintext (`8.192` percobaan):** Rata-rata jarak Hamming `63.9376 / 128` bit (**`49.9513%`**), simpangan baku `4.4103%`, minimum `34.375%`, maksimum `66.4062%`.
- **Efek Avalanche perubahan 1 bit kunci (`8.192` percobaan):** Rata-rata jarak Hamming `63.8917 / 128` bit (**`49.9154%`**), simpangan baku `4.4133%`, minimum `30.4688%`, maksimum `65.625%`.
- **SAC Empiris (`128 x 128 = 16.384` entri, `N = 64`):** Rata-rata `|p_hat - 0.5| = 0.049363`, maksimum `|p_hat - 0.5| = 0.25` (galat baku binomial pada $p = 0.5$, $N = 64$ adalah `0.0625`).
- **Benchmark Primitif Python Murni (`Python 3.13.14` pada `Windows-11-10.0.26200-SP0`, `warmup = 250`, `15` batch x `200` op):**
  - `key_schedule_128`: median `592.56 us/op` (`1687.6` op/detik)
  - `encrypt_block_with_schedule`: median `926.30 us/op` (`1079.56` op/detik)
  - `decrypt_block_with_schedule`: median `954.37 us/op` (`1047.81` op/detik)
  - `encrypt_block_oneshot`: median `1538.93 us/op` (`649.8` op/detik)
  - `decrypt_block_oneshot`: median `1635.85 us/op` (`611.3` op/detik)

> **Catatan Statistik:** Rata-rata avalanche di sekitar `50%` dan nilai SAC di sekitar `0.5` menunjukkan difusi empiris yang baik pada implementasi ini, tetapi **bukan** bukti matematis keamanan penuh terhadap kriptanalisis diferensial, linear, *impossible-differential*, atau integral.

---

## Panduan Deployment ke Vercel + PostgreSQL Terkelola

1. Siapkan layanan PostgreSQL terkelola (misalnya Neon atau Supabase) dan jalankan `uv run alembic upgrade head` dari shell tepercaya.
2. Impor repositori ini ke Vercel (konfigurasi menggunakan `app.py`, `pyproject.toml`, `uv.lock`, dan `vercel.json`).
3. Atur Variabel Lingkungan (*Environment Variables*) di Vercel:
   - `DATABASE_URL` (`postgresql+psycopg://...?sslmode=require`)
   - `CLEFIA_ENC_KEY_HEX` (kunci 128-bit acak baru sepanjang 32 karakter heksadesimal)
   - `CLEFIA_KEY_ID` (misalnya `prod-v2`)
   - `SESSION_SECRET_KEY` (string acak minimal 32 karakter)
   - `APP_ENV=production`
   - `DEMO_MAX_USERS=100`
4. Verifikasi layanan setelah deploy (`GET /health`, `/math`, `/experiments`, serta alur daftar $\rightarrow$ masuk $\rightarrow$ `/credentials` $\rightarrow$ `/profile` $\rightarrow$ `/change-password` $\rightarrow$ `/logout`).

---

## Daftar Periksa Demonstrasi (Antarmuka Bahasa Indonesia)

1. **Peringatan Akademis & Matematis (`/`, `/math`):** Tunjukkan spanduk peringatan akademis berbahasa Indonesia serta perhitungan langsung vektor uji resmi RFC 6114 (`de2bf2fd9b74aacdf1298555459494fd`) dan `Struktur Jaringan Feistel`.
2. **Pendaftaran & Penyimpanan Terenkripsi (`/register`, `/credentials`):** Daftarkan akun simulasi (mis. `mhs_demo_01` / `SandiSimulasi!01`), lalu tunjukkan tabel `Data Terenkripsi` yang hanya memperlihatkan ciphertext heksadesimal & nonce 12-byte untuk `Nama pengguna` dan `Kata sandi` (tanpa kata sandi teks biasa).
3. **Login Pendekatan A (`/login`):** Keluar dan masuk kembali dengan huruf kapital berbeda (mis. `MHS_DEMO_01`) untuk mendemonstrasikan kanonikalisasi `NFKC + strip + casefold` dan pemindaian dekripsi nama pengguna satu per satu.
4. **Catatan Profil Wajib (`/dashboard`, `/profile`):** Simpan catatan panjang berbahasa Indonesia (> 16 byte), lihat hasil dekripsi khusus pemilik, dan buktikan pengguna lain tidak dapat membacanya.
5. **Ubah Kata Sandi (`/change-password`):** Perbarui kata sandi simulasi dan tunjukkan nonce berubah sementara kata sandi lama ditolak.
6. **Eksperimen & Batasan Mode CTR (`/experiments`):** Tunjukkan grafik Efek Avalanche, SAC, dan Waktu Eksekusi berlabel Bahasa Indonesia, serta jelaskan keterbatasan mode CTR tanpa MAC, kata sandi reversibel, dan kompleksitas pemindaian O(n).
