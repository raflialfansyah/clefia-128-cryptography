# Product Requirements Document (PRD)
## CLEFIA-128: Mathematical Implementation and Academic Credential-Encryption Demonstrator

**Document type:** Implementation PRD and execution plan for an autonomous coding agent  
**Version:** 1.1 — revised academic credential-encryption scope  
**Date:** 2026-11-15  
**Language:** English  
**Project context:** Mathematics of Cryptography capstone  
**Status:** M0–M7 implemented per progress log; implement Change Request CR-001 for encrypted academic credentials

> **Instruction to the coding agent:** Read this entire document before editing the repository. Implement incrementally, in the order of the milestones below. The mathematical correctness of CLEFIA-128 takes precedence over UI completeness. Do not mark a milestone complete without running its acceptance tests and recording the results.

---

## 1. Executive Summary

Build a reproducible educational implementation of the **CLEFIA-128 block cipher entirely in Python**, then demonstrate its use in a small web application built with **FastAPI**, **Jinja2**, **PostgreSQL**, and deployed to **Vercel**.

The capstone's assignment is to reproduce the **application concept** of Gea (2022) using **different software**, not to implement the cipher in multiple languages or invent a new cryptographic algorithm. This project's distinctive contribution is a transparent mathematical implementation, verification against published CLEFIA test vectors, and measurable experiments on avalanche effect and execution time.

**Revised academic requirement:** In this educational demonstrator, **both username and password must be reversibly encrypted using CLEFIA-128** before persistence. Remove Argon2id entirely from the project; do not add a replacement password-hashing scheme. This deliberately departs from recommended production password storage. Use only synthetic credentials and display an unambiguous academic-only warning. Implement encrypted username lookup using a separately keyed HMAC-SHA-256 blind index so randomized encryption still supports unique usernames and efficient login; HMAC is supporting integrity/indexing, not the password-encryption algorithm. The encryption primitive under study remains CLEFIA-128.

This is an **academic prototype**, not a production-safe credential store. Reversible password encryption means server key compromise can expose passwords. Do not process real users' credentials or personal information. If publicly deployed, use clearly labeled synthetic/demo accounts and restrict access as appropriate; never advertise it as a production authentication system.

### 1.1 Scope at a glance

| Area | Required decision |
|---|---|
| Primary language | Python 3.12+ |
| Web framework | FastAPI |
| Server-side UI | Jinja2 + HTML/CSS; minimal JavaScript only if needed |
| Database | PostgreSQL |
| ORM / migrations | SQLAlchemy 2.x + Alembic |
| Credential storage | CLEFIA-128 CTR + HMAC-enveloped ciphertext for **username and password**; no password hash |
| Username lookup | Keyed HMAC-SHA-256 blind index of canonicalized username; distinct secret from record MAC key |
| Web deployment | Vercel Python/FastAPI runtime |
| Unit/integration tests | pytest, FastAPI TestClient/httpx |
| Benchmark/analysis | Python standard library; NumPy, pandas, matplotlib optional for analysis |
| Cipher core | **Written from scratch in Python; no external CLEFIA implementation** |
| Source of mathematical truth | Sony CLEFIA specification and IETF RFC 6114 |
| Dataset | Synthetic test records only |

### 1.2 Deliverables

1. Working and tested pure-Python CLEFIA-128 module.
2. Unit tests using published block and intermediate-value test vectors.
3. An authenticated CLEFIA-CTR record wrapper for variable-length encrypted username, password, and mandatory synthetic profile note; preserve separation from the raw block cipher.
4. A FastAPI application supporting registration, login, CLEFIA-encrypted credentials, mandatory profile note encryption/decryption (`/profile`), and logout.
5. PostgreSQL schema and database migrations.
6. Reproducible avalanche-effect, Strict Avalanche Criterion (SAC), and performance experiments with saved CSV/JSON outputs and visualizations.
7. Locally runnable project, Vercel deployment instructions, and a demonstration checklist.
8. README explaining mathematics, setup, limitations, and reproducibility.

---

## 2. Problem, Motivation, and Academic Alignment

### 2.1 Problem statement

Gea (2022) describes a web-based application of CLEFIA-128 for user-login records and presents ciphertext and successful encryption/decryption examples. The capstone will reproduce the baseline idea of applying CLEFIA directly to synthetic login credentials, but with a **Python/FastAPI/PostgreSQL** implementation and a more explicit validation and experimental methodology.

### 2.2 Academic questions

- **RQ1:** How can the mathematical components of CLEFIA-128 be implemented correctly in Python according to the published specification?
- **RQ2:** How can a verified CLEFIA-128 core be integrated into a FastAPI web application to encrypt and recover **synthetic usernames and passwords**?
- **RQ3:** How do published test vectors, controlled avalanche/SAC experiments, and execution-time measurements characterize implementation correctness and observable behavior?

### 2.3 Success criteria

- The official CLEFIA-128 test vector matches **exactly**.
- Encryption and decryption are correct for a broad deterministic random test set.
- An academic account registration/login flow works with **no plaintext username or password and no password hash in the database**; username and password are recoverable only via the CLEFIA record-decryption path.
- A keyed username blind index supports unique usernames and lookup without storing the plaintext username; the mandatory `profile_note` feature preserves its existing CLEFIA-128 encryption/decryption workflow, `/profile` routes, CSRF protection, and owner isolation.
- Corrupted or forged encrypted records fail authentication before decryption.
- Avalanche/SAC and benchmark programs produce reproducible, labeled results.
- The web app runs locally, all tests pass, and the Vercel deployment is demonstrable.

### 2.4 Non-goals

- Implementing CLEFIA-192 or CLEFIA-256.
- Comparing Python to C, TypeScript, or another language.
- Building an enterprise identity provider, email verification, or password recovery service.
- Claiming avalanche results prove resistance to differential/linear cryptanalysis.
- Inventing a new cipher, key schedule, S-box, or mode of operation.
- Publishing real encryption keys, plaintext/decrypted credentials, or personal data in screenshots, logs, or Git.

---

## 3. Reference Hierarchy and Traceability

Follow sources in this order when an implementation detail is ambiguous:

1. **Primary specification:** Sony, *The 128-bit Blockcipher CLEFIA*, version 1.0.  
   https://www.sony.co.jp/en/Products/cryptography/clefia/download/data/clefia-spec-1.0.pdf
2. **Detailed public algorithm and intermediate test values:** Katagi & Moriai, *RFC 6114: The 128-Bit Blockcipher CLEFIA* (2011).  
   https://www.rfc-editor.org/rfc/rfc6114.html
3. **Original design paper:** Shirai, Shibutani, Akishita, Moriai & Iwata, *The 128-bit Blockcipher CLEFIA* (2007), supplied with the capstone materials.
4. **Application baseline only:** Gea, *Analisis dan Implementasi Algoritma CLEFIA 128 untuk Meningkatkan Confusion Record Data Login User* (2022), supplied with the capstone materials.
5. **Project academic scope:** revised capstone BAB 1–2 DOCX (`Capstone_CLEFIA128_BAB1_BAB2_Revisi_Matematis_Word_Equation.docx`).

**Conflict rule:** Use the Sony specification / RFC 6114 to resolve mathematical discrepancies in the 2022 application paper. Do not silently replicate apparent typos, unsubstantiated security claims, or incorrect character-based ciphertext representations.

**Agent traceability rule:** In the `docs/mathematics.md` file, annotate each implemented component with its corresponding RFC/Sony section. Attribute copied S-box/constant tables clearly.

---

## 4. Product Users and User Stories

### 4.1 Personas

- **Student/developer:** needs to inspect algorithm modules, run official vectors, and produce a reproducible experimental report.
- **Lecturer/evaluator:** needs to try a small demonstrator, verify correctness evidence, and understand which mathematical mechanisms are implemented.
- **Demo user:** registers with a synthetic username and password; can inspect ciphertext metadata for each credential after authenticating, without displaying decrypted passwords.

### 4.2 User stories

| ID | Story | Acceptance outcome |
|---|---|---|
| US-01 | As a student, I can run official vectors | The expected ciphertext is displayed and test assertions pass |
| US-02 | As a student, I can inspect component-level tests | GF multiplication, S-boxes, F-functions, key schedule, and rounds are individually testable |
| US-03 | As a demo user, I can register and log in | Username and password are encrypted under CLEFIA; login performs authenticated decryption and constant-time password comparison |
| US-04 | As a demo user, I can inspect credential ciphertext | Only the authenticated owner sees hex/Base64 ciphertext, nonce, tag, and metadata; no clear password/key |
| US-05 | As a demo user, I can change my demo password | The stored encrypted password is replaced using a fresh nonce; old password no longer authenticates |
| US-06 | As an evaluator, I can see an explanation of CLEFIA | UI/docs present GFN, S-boxes, finite fields, DoubleSwap, and tests |
| US-07 | As a student, I can reproduce the experiments | A fixed seed and documented parameters recreate numerical outputs |
| US-08 | As an evaluator, I can inspect deployment | Demo is reachable over HTTPS and its configuration has no committed secrets |

---

## 5. Mathematical and Cryptographic Requirements

### 5.1 Bit conventions

- Operate on **128-bit blocks (16 bytes)** and **128-bit keys (16 bytes)**.
- Represent blocks as exactly four **32-bit words** in the byte/bit ordering specified by Sony/RFC 6114.
- Keep 8-, 16-, 32-, and 128-bit boundaries explicit; mask after shifts when necessary.
- Distinguish concatenation (`||`), bitwise XOR (`⊕`), and multiplication over finite fields.
- Reject keys or blocks of incorrect lengths rather than silently padding/truncating.

The block cipher with a fixed key is a permutation:

\[
E_K:\{0,1\}^{128}\longrightarrow\{0,1\}^{128},\qquad
D_K(E_K(P))=P.
\]

### 5.2 Required components

Implement these as testable pure functions/classes without importing FastAPI or SQLAlchemy:

| ID | Component | Specification |
|---|---|---|
| CR-01 | Byte/word conversion | Explicit ordering, 16-byte input/output, 32-bit word serialization |
| CR-02 | `gf_mul8(a, b)` | Multiplication in GF(2^8) modulo `x^8 + x^4 + x^3 + x^2 + 1` (`0x11D`) |
| CR-03 | CLEFIA `S0`, `S1` | Exact 256-entry lookup tables or demonstrably equivalent construction from specification |
| CR-04 | `F0(round_key, word)` | XOR, S-box order `S0,S1,S0,S1`, matrix `M0` |
| CR-05 | `F1(round_key, word)` | XOR, S-box order `S1,S0,S1,S0`, matrix `M1` |
| CR-06 | Matrix transforms | Multiply 4-byte vectors by `M0`/`M1` in GF(2^8), not integer arithmetic |
| CR-07 | `gfn4` and inverse | Four-branch generalized Feistel network, prescribed branch rotations |
| CR-08 | `double_swap` | Exact 128-bit Sigma permutation, not a general-purpose bit rotation |
| CR-09 | Key-schedule constants | 60 CLEFIA-128 32-bit constants or their correct reproducible generator |
| CR-10 | `key_schedule_128` | Intermediate `L`, 4 whitening words, 36 round-key words |
| CR-11 | `encrypt_block` | 18-round CLEFIA-128 with correct whitening positions |
| CR-12 | `decrypt_block` | Exact inverse with inverse GFN and correct whitening positions |

**GF(2^8):**

\[
GF(2^8) \cong GF(2)[x]/(p(x)),\quad
p(x)=x^8+x^4+x^3+x^2+1.
\]

Matrix multiplication over this field uses XOR for field addition. The two matrices are:

\[
M_0=\begin{bmatrix}
01&02&04&06\\02&01&06&04\\04&06&01&02\\06&04&02&01
\end{bmatrix},\quad
M_1=\begin{bmatrix}
01&08&02&0a\\08&01&0a&02\\02&0a&01&08\\0a&02&08&01
\end{bmatrix}
\]

All entries above are **hexadecimal field elements**, not decimal integers.

**One generalized Feistel round** (before prescribed branch rotation):

\[
T_1\leftarrow T_1\oplus F_0(RK_{2i},T_0),\qquad
T_3\leftarrow T_3\oplus F_1(RK_{2i+1},T_2).
\]

The implementation must follow the official *final output order* and input/output whitening exactly. Do not replace CLEFIA with a conventional two-branch Feistel construction.

**Key schedule:** CLEFIA-128 derives `L` with `GFN_{4,12}` using the first 24 constants; whitening words come from the user key; nine iterations derive 36 round-key words, with Sigma (DoubleSwap) and odd-iteration key XOR. Use the specified GF(2^16) polynomial (`0x1A831`) when generating key-schedule constants.

### 5.3 Mandatory official vector (release blocker)

```text
KEY        = ffeeddccbbaa99887766554433221100
PLAINTEXT  = 000102030405060708090a0b0c0d0e0f
CIPHERTEXT = de2bf2fd9b74aacdf1298555459494fd
```

From RFC 6114, Appendix B, also verify selected intermediate outputs:

```text
INTERMEDIATE_L = 8f89a61b9db9d0f393e65627da0d027e
WK0..WK3      = ffeeddccbbaa99887766554433221100
RK0..RK3      = f3e6cef98df75e3841c06256640ac51b
RK32..RK35    = a34a20f533265d14b19d05545142f434
```

**Acceptance:** `encrypt_block(key, plaintext) == expected_ciphertext` and `decrypt_block(key, ciphertext) == plaintext`. If this fails, **do not proceed to the web application**. Debug byte order, S-box values, GF arithmetic, matrix transforms, GFN rotation, whitening, and key scheduling against RFC intermediate values. Do not hardcode ciphertext for the test vector.

### 5.4 Variable-length credentials and data: authenticated encryption wrapper

CLEFIA-128 is only a block permutation, **not by itself a safe record-encryption format**. For this academic demo, implement a clearly separated, versioned wrapper with:

- **CLEFIA-CTR** for confidential variable-length data.
- A **fresh, unique 96-bit nonce** for each encryption under the same key, followed by a 32-bit big-endian counter starting at `1` (together forming the 16-byte counter block).
- Overflow and message-length checks (reject if a 32-bit counter would wrap).
- **Encrypt-then-MAC with HMAC-SHA-256**, using a cryptographically independent authentication key.
- Authentication binding the version, key identifier, record owner ID, field identifier, nonce, and ciphertext using an unambiguous, length-prefixed binary encoding. Authenticate **before** attempting decryption.
- Constant-time tag checks using `hmac.compare_digest`.
- A version/key-id field to make the storage format explicit and support future migrations.
- No ECB mode, fixed nonce, deterministic nonce reuse, or unauthenticated CTR in the web application.

Suggested wrapper interface:

```python
def encrypt_record(plaintext: bytes, *, owner_id: str, field_name: str) -> EncryptedRecord: ...
def decrypt_record(record: EncryptedRecord, *, owner_id: str, field_name: str) -> bytes: ...
```

**Required demo key configuration:** independent environment-provided `CLEFIA_ENC_KEY_HEX` (16 bytes), `CLEFIA_MAC_KEY_HEX` (32 bytes), `USERNAME_INDEX_KEY_HEX` (32 bytes), and `SESSION_SECRET_KEY`. The index key MUST NOT equal the record MAC key. Never derive the MAC key by duplicating the encryption key. Prefer randomly generated keys; document safe creation commands. Keep test-only fixed keys in tests, never production configuration.

**Nonce uniqueness implementation:** generate with `secrets.token_bytes(12)` and enforce a database uniqueness constraint on `(key_id, nonce)` for encrypted records, retrying a collision. The key ID is metadata, not a secret. Handle zero-length and UTF-8 inputs correctly. Support tamper detection for nonce, ciphertext, tag, and associated data.

> **Security note:** This custom combination is included as a transparent educational exercise. It is not audited. For production-sensitive data, use a vetted authenticated-encryption library/protocol rather than treating this project as a security product.

---

### 5.5 Encrypted credential registration and login (academic only)

- On registration, canonicalize the username using a single documented algorithm (for example: Unicode NFC normalization and `casefold()`, with whitespace rules explicit). Enforce username uniqueness via `HMAC-SHA-256(USERNAME_INDEX_KEY, b"clefia-username-index-v1\0" || UTF8(canonical_username))`. Store this **blind index**, never the canonical plaintext username.
- Generate one UUID user ID. Encrypt `UTF8(canonical_username)` and `UTF8(password)` separately using the existing CLEFIA-CTR+HMAC `encrypt_record` service with `owner_id=user_id` and `field_name="username"` / `"password"`. Use a fresh random nonce for each field and authentication bind the owner and field name.
- On login, re-canonicalize the input username, compute its keyed index, load the user and **both encrypted credential records**, verify both tags, decrypt the stored username and require it to match the canonicalized candidate, then decrypt the password server-side and compare password bytes with `hmac.compare_digest`. Do not persist or display the decrypted password.
- Reject malformed, missing, or tampered credential ciphertext; retain generic login errors and throttling. Re-encrypt with a new nonce when changing a password.
- HMAC used for the **lookup index** and **tamper detection** is a supporting construction; **CLEFIA-128 performs all credential encryption/decryption**. Do not substitute a deterministic reused-nonce CTR design just to make usernames searchable.
- Never use this scheme for actual accounts, real passwords, or production security guarantees. Explain why reversible password storage is unsuitable for production systems.

## 6. Web Application Requirements

### 6.1 Features

| ID | Feature | Priority | Acceptance condition |
|---|---|---|---|
| FR-01 | Register account | Must | Username lookup index unique; username and password are CLEFIA-encrypted before database write; no plaintext/password hash columns |
| FR-02 | Log in/log out | Must | Resolve username by keyed blind index; authenticate/decrypt and check stored username; authenticate/decrypt password and compare constant-time; manage session |
| FR-03 | View own credential-encryption metadata | Must | Logged-in demo owner sees ciphertext, nonce, tag for username/password; no plaintext password or keys |
| FR-04 | Change demo password | Must | Password re-encrypted with a fresh nonce; old password rejected |
| FR-05 | Encrypted profile note | Must | Preserve mandatory owner-authorized CLEFIA-128 encrypted note workflow, `/profile` routes, DB persistence, templates, CSRF protection, and owner isolation |
| FR-06 | Math/explanation page | Should | Explains block structure, GFN, S-box, GF(2^8), avalanche methodology |
| FR-07 | Experiment results page | Should | Loads committed sample charts/results; does not run heavy experiments per request |
| FR-08 | Health check | Must | `/health` returns service status without exposing secrets |
| FR-09 | Accessible, simple interface | Should | Desktop/mobile usable; clear form errors and basic accessibility |

### 6.2 Suggested routes

| Method + route | Purpose | Access |
|---|---|---|
| `GET /` | Landing page and project explanation | Public |
| `GET /register` | Registration form | Public |
| `POST /register` | Create user | Public, rate-limited |
| `GET /login` | Login form | Public |
| `POST /login` | Authenticate | Public, rate-limited |
| `POST /logout` | End session | Authenticated |
| `GET /dashboard` | Profile and encryption status | Authenticated |
| `GET /credentials` | Academic visualization of username/password ciphertext and metadata; never show decrypted password | Authenticated |
| `POST /change-password` | Replace encrypted synthetic password (fresh nonce) | Authenticated + CSRF |
| `POST /profile` | Mandatory profile-note encryption save/update | Authenticated + CSRF |
| `GET /profile` | Mandatory owner-authorized profile note view | Authenticated |
| `GET /math` | Algorithm and mathematical explanations | Public |
| `GET /experiments` | Static/precomputed results and plots | Public |
| `GET /health` | Minimal service health | Public |

**Session design:** Use properly signed Secure/HttpOnly/SameSite cookies (with only non-sensitive session data), or database-backed sessions, via appropriate FastAPI/Starlette middleware; require HTTPS in deployment, session renewal at login, explicit logout, CSRF protection for browser state-changing forms, and durable/edge-compatible login rate limits for a public demo. Do not store a plaintext password or secret key in a cookie. If durable rate limiting cannot be configured, restrict deployment access and document the limitation.

### 6.3 Suggested database schema

A minimal relational design (final migrations are authoritative):

```text
users
  id                   UUID PRIMARY KEY
  username_lookup      BYTEA UNIQUE NOT NULL     -- 32-byte HMAC blind index
  created_at           TIMESTAMPTZ NOT NULL

user_encrypted_fields
  id                   UUID PRIMARY KEY
  owner_id             UUID NOT NULL REFERENCES users(id)
  field_name           VARCHAR NOT NULL    -- 'username' / 'password' / 'profile_note' (mandatory features)
  key_id               VARCHAR NOT NULL
  algorithm_version    SMALLINT NOT NULL
  nonce                BYTEA NOT NULL       -- 12 bytes
  ciphertext           BYTEA NOT NULL
  auth_tag             BYTEA NOT NULL       -- 32 bytes, HMAC-SHA-256
  updated_at           TIMESTAMPTZ NOT NULL
  UNIQUE(owner_id, field_name)
  UNIQUE(key_id, nonce)
```

Rules: never store plaintext username, plaintext password, or a password hash in the database; the indexed value is an independently keyed HMAC blind index. Encrypt both username and password via CLEFIA before insert. Use SQLAlchemy parameterized queries; never log raw/decrypted credentials or crypto keys. Support test-only synthetic credentials; do not use BigQuery.

### 6.4 Environment configuration

Provide `.env.example` without real values. Expected variables:

```text
DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME
CLEFIA_ENC_KEY_HEX=<32_HEX_CHARS>
CLEFIA_MAC_KEY_HEX=<64_HEX_CHARS>
USERNAME_INDEX_KEY_HEX=<64_HEX_CHARS>
CLEFIA_KEY_ID=demo-v1
SESSION_SECRET_KEY=<LONG_RANDOM_SECRET>
APP_ENV=development
```

Validate secrets' format and length at startup; fail closed on missing/malformed secrets. Add `.env` and generated experiment caches to `.gitignore` as appropriate. Do not silently substitute default production secrets.

---

## 7. Mathematical Experiments and Reporting

Experiments operate on the **raw 128-bit CLEFIA block primitive**, not on the randomized record-encryption wrapper (where nonce randomness would confound plaintext-change measurements).

### 7.1 Correctness tests

- Published vector and RFC intermediate values (mandatory).
- `decrypt_block(K, encrypt_block(K, P)) == P` for a **seeded deterministic sample** of at least 1,000 `(K, P)` pairs.
- Boundary cases: all-zero/all-one keys and blocks, incremental bytes, high-bit values.
- Validate incorrect key/input sizes raise informative exceptions.
- Unit tests for S-box indexes, GF multiplication, matrices, key-schedule sizes and byte order.

### 7.2 Avalanche effect

For fixed `K`, take `P^(i) = P XOR 2^i`, changing exactly one bit. Define:

\[
A_i(K,P)=\frac{\operatorname{HD}(E_K(P),E_K(P^{(i)}))}{128}\times100\%.
\]

- Use a configurable fixed pseudorandom seed (default `20261115`) for reproducibility.
- Suggested baseline: **64 independent `(K,P)` pairs**, testing all **128 plaintext bit positions** for each pair. This is a proposal, not a claim that 64 samples are statistically sufficient for every inference.
- Repeat as a **separate experiment** with one-bit changes in the encryption key.
- Save raw per-trial outputs (or sufficient nonsecret bit-change summaries), metadata, sample count, seed, and aggregate mean/standard deviation.
- Use diagrams: output Hamming-distance histogram and avalanche-by-input-position plot.
- Explain that approximately 50% mean bit changes is an empirical diffusion indicator, **not a proof of cryptographic security**.

### 7.3 Empirical Strict Avalanche Criterion (SAC)

Estimate, for each input bit `i` and output bit `j`:

\[
\widehat p_{ij}=\frac{1}{N}\sum_{s=1}^{N}
\mathbf{1}\left[E_K(P_s)_j\ne E_K(P_s\oplus2^i)_j\right].
\]

- Save `128 x 128` probability matrix for plaintext flips.
- Produce a heatmap and report average absolute deviation from `0.5`.
- Record uncertainty from finite sampling; do not claim a formal SAC proof.

### 7.4 Performance benchmark

- Benchmark **primitive** key setup, single-block encryption, and decryption separately.
- Use `time.perf_counter_ns()` locally; exclude database/network/rendering overhead.
- Pin/document Python version, OS, CPU, test size, warm-up passes, iteration counts, and random seed.
- Use multiple batches and report median, mean, and p95 where appropriate; show units (ns/block, µs/block, or blocks/s).
- Optionally add a **separate** end-to-end API latency measurement. Do not compare it directly with primitive time.
- No fixed performance target is required; correctness and reproducibility are more important than speed.

### 7.5 Experiment artifacts

Generate, or document commands that generate:

```text
experiments/results/avalanche_plaintext.csv
experiments/results/avalanche_key.csv
experiments/results/sac_matrix.csv
experiments/results/benchmark.json
experiments/plots/avalanche_histogram.png
experiments/plots/avalanche_positions.png
experiments/plots/sac_heatmap.png
experiments/plots/benchmark.png
```

Do not manufacture numbers. Place generated figures and measured values into the README/report only after the scripts actually run. If a resource-intensive experiment cannot finish in the agent environment, report the partial result and a precise local reproduction command.

---

## 8. Architecture and Repository Structure

### 8.1 Layered architecture

```text
Browser (HTML/CSS/Jinja2)
        |
        v
FastAPI routes + session/auth + CSRF checks
        |
        +-----> Username HMAC blind-index lookup (no plaintext index)
        |
        +-----> Credential record encryption (CLEFIA-CTR + HMAC-SHA-256)
        |                 |
        |                 v
        |           Pure Python CLEFIA-128 primitive
        |
        v
PostgreSQL (blind username index + encrypted username/password fields + metadata)

Offline command-line experiments
        |
        v
Pure Python CLEFIA-128 primitive --> CSV/JSON/plots
```

### 8.2 Proposed repository

```text
clefia128-capstone/
├── README.md
├── PRD.md                          # copy of this file
├── pyproject.toml
├── uv.lock / requirements.lock     # one reproducible dependency lock strategy
├── .env.example
├── .gitignore
├── Dockerfile                      # optional local development only
├── docker-compose.yml              # local PostgreSQL
├── app.py                          # recognized Vercel FastAPI entrypoint
├── src/
│   ├── clefia/
│   │   ├── __init__.py
│   │   ├── constants.py
│   │   ├── field.py
│   │   ├── sboxes.py
│   │   ├── functions.py
│   │   ├── gfn.py
│   │   ├── key_schedule.py
│   │   ├── cipher.py
│   │   └── record_crypto.py
│   └── web/
│       ├── config.py
│       ├── db.py
│       ├── models.py
│       ├── schemas.py
│       ├── auth.py
│       ├── routes.py
│       ├── templates/
│       └── static/
├── alembic/
├── tests/
│   ├── test_field.py
│   ├── test_sboxes.py
│   ├── test_functions.py
│   ├── test_key_schedule.py
│   ├── test_vectors.py
│   ├── test_roundtrip.py
│   ├── test_record_crypto.py
│   ├── test_auth.py
│   └── test_routes.py
├── experiments/
│   ├── avalanche.py
│   ├── sac.py
│   ├── benchmark.py
│   ├── results/
│   └── plots/
├── docs/
│   ├── mathematics.md
│   ├── architecture.md
│   ├── threat_model.md
│   └── experiment_protocol.md
└── .github/workflows/test.yml
```

**Packaging clarification:** If using a `src/` layout, configure packaging and Python imports correctly. Keep the importable cryptography module independent of web-framework dependencies. `app.py` must export a FastAPI object named `app` for Vercel's framework detection.

---

## 9. Agent Execution Plan and Milestone Gates

The AI coding agent must complete milestones sequentially. A **gate** is not passed merely because files exist; tests and documented evidence are required.

| Stage | Work package | Deliverable | Mandatory gate |
|---|---|---|---|
| M0 | Repository bootstrap | `pyproject.toml`, lockfile, README skeleton, lint/test config, CI | `pytest` runs; minimal FastAPI starts locally |
| M1 | Mathematical primitives | Field arithmetic, S-boxes, F0/F1, matrices, GFN, DoubleSwap | Focused unit tests pass; documented mapping to RFC |
| M2 | CLEFIA core | Constants, key schedule, encrypt/decrypt blocks | **Official vector + RFC intermediate checks pass** |
| M3 | Record-crypto wrapper | CTR, nonce, HMAC EtM, serialization, key configuration | Round-trip and tamper tests pass; two encryptions produce different nonces |
| M4 | Persistence/authentication | Encrypted username/password + HMAC username index, migrations, sessions; remove password-hashing dependency | Register/login/logout tests; no plaintext username/password or password_hash in DB |
| M5 | UI and routes | Jinja2 forms, credential ciphertext page, password change, math page, and mandatory `/profile` note UI | Credential and profile encryption visible; no password decryption shown; CSRF and owner tests pass |
| M6 | Mathematical experiments | Avalanche/SAC/benchmark scripts + CSV/plots | Reproducible runs; actual files and parameter metadata exist |
| M7 | Deployment/QA/docs | Vercel setup, CI, README, threat model, demo script | All gates pass, deployment works, no committed secrets |

### 9.1 Milestone-by-milestone directions

**M0 — Bootstrap**
- Create a runnable and importable Python project. Use a single dependency management system.
- Configure `pytest`, basic linting (`ruff` recommended), `.gitignore`, `.env.example`, and a GitHub Actions test workflow.
- Provide local PostgreSQL via Docker Compose, but keep mathematical tests independent of Docker.

**M1 — Primitive mathematics**
- Implement arithmetic and lookup operations before integrating rounds.
- Write tests for the GF polynomial `0x11D`, proper matrix multiplication, S-box boundaries, and inverse structural operations where applicable.
- Document MSB ordering and countercheck official S-box table values.

**M2 — Full block cipher**
- Add key schedule and full 18-round encryption/decryption.
- Assert the official vector and Appendix B intermediate values; do not move forward if any mismatch.
- Generate deterministic random round-trip tests. Keep a short trace/debug mode for test use only, without logging production secrets.

**M3 — Safe educational record wrapper**
- Define the exact binary format and field lengths in `docs/architecture.md`.
- Implement nonce generation, CTR counter blocks, HMAC binding, tag verification before decryption, and fail-closed errors.
- Include tests for wrong key, wrong owner AAD, wrong field name, modified nonce, modified ciphertext, and modified tag.

**M4 — Auth/database**
- Refactor the completed M4 implementation: remove `PasswordHasher`, all password-hash fields, tests, and password-hashing dependencies.
- Add `users.username_lookup` as a unique keyed HMAC blind index with a **distinct lookup secret**; the raw username is encrypted as a normal CLEFIA field.
- Reuse/generalize the existing `RecordCryptoService` for username and password. Create each user UUID before encrypting fields so owner/field AAD remains stable.
- Verify the password only after authenticated CLEFIA decryption, using constant-time comparison; preserve rate limits, session management, CSRF, and owner isolation.
- Make the migration strategy explicit: a clean reset is acceptable **only** for synthetic academic demo data; otherwise provide a safe migration requiring the user's plaintext password for re-encryption rather than attempting to recover it from the old Argon2id hash.

**M5 — Web interface**
- Refactor existing templates to explain synthetic username/password CLEFIA encryption, expose metadata only to the logged-in owner, and support password change. Retain existing login/register/dashboard/math/experiment routes.
- Build a minimal academic demonstrator, not a complex SPA.
- Avoid exposing a general-purpose encryption oracle on public routes.
- Show a mathematically explained test vector on `/math` using fixed public sample values, not an actual secret.

**M6 — Research evaluation**
- Implement deterministic CLI programs; save seed, time, environment, and sample size alongside output.
- Render plots from measured data. Separate primitive benchmarks from app/API benchmarks.
- Record observed deviations and limitations without overstating security.

**M7 — Deployment and handoff**
- Use the supported FastAPI entrypoint/configuration from current Vercel docs.
- Store credentials in deployment environment settings, not in Git.
- Ensure serverless database connections are bounded and reused appropriately; no expensive experiment in a request handler.
- Run the final demo checklist and document exact startup/deploy commands.

---

## 10. Test and Acceptance Matrix

| ID | Test | Required result |
|---|---|---|
| T-001 | Sony/RFC CLEFIA-128 official vector | Exact `de2bf2fd9b74aacdf1298555459494fd` |
| T-002 | RFC intermediate `L`, first/last round keys | Exact published values |
| T-003 | 1,000 deterministic random block round-trips | 100% pass |
| T-004 | Wrong block/key sizes | Correct explicit exception |
| T-005 | Two encryptions of same username or password | Distinct nonces and usually ciphertexts; each decrypts to identical input |
| T-006 | Flip one bit of nonce/ciphertext/tag | Reject before decrypt; no plaintext returned |
| T-007 | Swap owner ID or field name in AAD | Reject |
| T-008 | Register/login/logout | Lookup by HMAC index, username/password CLEFIA-encrypted at rest; correct input logs in and wrong password fails |
| T-009 | Access another user's encrypted credential or profile_note record | Denied (owner-isolated), including ciphertext metadata |
| T-010 | Browser write without CSRF token | Denied |
| T-011 | Avalanche/benchmark repeatability | Same seed/config gives same input set; timing may vary, report variability |
| T-012 | Secrets in repository/config/output | No real keys/plaintext credentials in source control, logs, response bodies, or templates |
| T-013 | PostgreSQL integration tests | Migrations and basic CRUD work against PostgreSQL |
| T-014 | Deployment smoke test | `GET /health`, synthetic credential registration, login, ciphertext visualization, password change, logout all work |
| T-015 | Password-hashing removal | No Argon2 package/import/model/column; `pyproject.toml`, lockfile, docs, CI, tests align |
| T-016 | Credential DB snapshot | No raw username, raw password, or password hash; two protected field envelopes plus keyed username lookup index |
| T-017 | Username duplicate/tamper | Unicode canonicalization stable; duplicates rejected; cross-user swap and ciphertext/tag modification rejected |

**Final Definition of Done:** all Must requirements and all T-001 through T-017 pass, code is documented, experiments have real outputs, and a reviewer can reproduce the project from a clean checkout.

---

## 11. Quality, Security, and Scientific Integrity Requirements

### 11.1 Engineering quality

- Type hints on public Python APIs; docstrings for mathematical functions and cryptographic assumptions.
- Small composable functions; no cryptographic implementation hidden inside route handlers.
- No arbitrary truncation/padding of a raw 128-bit block.
- No plaintext **username or password** storage; no stored password hash. Never log or render decrypted passwords. No `pickle` deserialization, raw SQL string concatenation, or global exception handlers that reveal secrets.
- Structured errors and HTTP status codes; no stack traces or sensitive material in public responses.
- Lock dependencies, keep key packages maintained, and document deployment constraints.

### 11.2 Security and threat model

Model: exposed database snapshot, reversible password exposure after key compromise, guessed usernames, unauthorized credential access, record tampering, nonce reuse, leaked environment secrets (encryption, MAC, lookup), SQL injection, brute-force login attempts, session theft, and CSRF.

The encrypted record wrapper provides confidentiality and tamper detection **only while encryption and MAC keys remain secret and nonce handling is correct**. It does not stop server compromise, stolen active sessions, or logical authorization errors. Document these boundaries in `docs/threat_model.md`.

### 11.3 Scientific integrity

- Cite the math from Sony/RFC and clearly distinguish the original CLEFIA design from this implementation.
- Use the original 2022 article only to establish the application baseline, not as the authoritative cipher specification.
- Do not report theoretical security proofs based on empirical 50% avalanche averages.
- Do not fabricate timing numbers, p-values, screenshots, or test-pass claims.
- If a test fails, describe the discrepancy and fix it; never alter official expected values to make tests green.

---

## 12. Recommended Local Commands

The agent must implement and verify the real commands in the README; examples:

```bash
# Install using the project's chosen package manager
python -m pip install -e '.[dev]'

# Start PostgreSQL locally (if Docker Compose is selected)
docker compose up -d db

# Apply migrations
alembic upgrade head

# Run correctness tests
pytest -q

# Run a local dev server
uvicorn app:app --reload

# Produce the research results
python -m experiments.avalanche --seed 20261115 --samples 64
python -m experiments.sac --seed 20261115 --samples 64
python -m experiments.benchmark --seed 20261115
```

**Important:** These are *target interfaces*, not a claim that they work before the code exists. Make command names and package paths consistent with the eventual repository.

---

## 13. Demonstration Walkthrough for the Lecturer

1. Open the mathematical explanation page and show the CLEFIA-128 components.
2. Run `pytest tests/test_vectors.py -q` and show the published expected ciphertext.
3. Show the Appendix B intermediate `L` and round-key assertions.
4. Register a **synthetic** user with a demo username and password; explain both are CLEFIA-encrypted.
5. Inspect database rows showing `username_lookup`, plus ciphertext/nonce/tag for both fields. Verify no username/password plaintext or password hash is stored.
6. Log out and log in with the same synthetic credentials, showing the server performs authenticated CLEFIA password decryption and comparison. Never display the decrypted password.
7. Demonstrate that a changed authentication tag or ciphertext is rejected.
8. Show an avalanche histogram, a SAC heatmap, and benchmark results with seed/metadata.
9. Explain what the experiments do **and do not** establish about security.
10. Show the Vercel URL and the reproducibility instructions.

---

## 14. Risks, Dependencies, and Fallbacks

| Risk / blocker | Mitigation |
|---|---|
| Misread finite-field polynomial (`0x11D` vs another AES-related polynomial) | Implement focused GF tests against CLEFIA source, inspect RFC intermediate values |
| Inaccurate word order/whitening/round rotation | Official full and intermediate test vectors are hard release gates |
| AI agent shortcuts by using another CLEFIA library | Prohibit as implementation; external implementations may be used only for independent verification, clearly documented |
| Academic reversible password encryption | Synthetic credentials only; prominent non-production warning; separate keys; never display/log decrypted password; protect demo access |
| Unauthenticated CTR or nonce collision | HMAC EtM, DB uniqueness, explicit counter format, tamper tests |
| Serverless SQL connections fail under load | Use a hosted PostgreSQL provider with serverless-compatible pooling; test deployment with real database settings |
| Heavy experiments time out on Vercel | Run offline locally/CI; serve saved plots rather than calculating in HTTP handlers |
| Too much feature scope for the capstone | Prioritize correctness > reproducibility > data-flow demonstration > UI refinement |
| Missing secret configuration at deployment | Startup validation and documented Vercel environment variables |

---

## 15. Open Decisions and Explicit Defaults

The following are **PRD implementation choices**, not statements taken directly from the source papers:

1. **Encrypted fields:** `username`, `password`, and `profile_note` are all mandatory CLEFIA-protected synthetic fields stored in `user_encrypted_fields`.
2. **Encryption wrapper:** CLEFIA-CTR + HMAC-SHA-256 EtM with 96-bit nonce and 32-bit counter; document byte format exactly and test it.
3. **Web authentication:** username keyed blind-index lookup plus verification of the encrypted username and CLEFIA-decrypted password comparison; retain HttpOnly sessions, CSRF protection, throttling, generic failures, and all owner checks.
4. **UI:** conventional FastAPI + Jinja2 templates, not a separate SPA.
5. **Baseline experiment:** 64 `(key, plaintext)` samples and all 128 plaintext bit flips; values configurable via CLI.
6. **Deployment:** Vercel demonstration with a hosted PostgreSQL service; deployment account/provider and URL supplied during deployment.
7. **Database access:** SQLAlchemy 2.x, psycopg, and Alembic.

If a default conflicts with a current authoritative specification or has a security defect, **stop, document the issue, and propose a narrowly scoped correction** before changing the core design. Avoid unnecessary framework substitutions.

---

## 16. Ready-to-Paste Agent Assignment

Use the following to start an AI coding agent:

> Continue the **existing** CLEFIA-128 Python/FastAPI repository from the current `docs/agent_progress.md`. Do **not** restart M0–M7; the original mathematical implementation and published test-vector validation are already reported as complete. Read `CLEFIA128_CREDENTIALS_AGENT_CHANGE_REQUEST.md` and execute **CR-001** in order. Remove all password hashing, persist synthetic username and password as authenticated randomized CLEFIA-CTR ciphertext, use a **separate HMAC-SHA-256 keyed username blind index** for uniqueness and login lookup, and verify both encrypted credential records before accepting login. Preserve the existing registered-user session controls, CSRF, login throttling, owner isolation, CLI mathematical experiments, and all official CLEFIA vectors. Update SQLAlchemy models, Alembic migrations, routes/templates, docs, dependencies, and tests. Never display decrypted passwords or put real passwords into the demo. Run the full suite and record actual results in `docs/agent_progress.md`; leave live PostgreSQL/Vercel items pending if the environment is not provisioned.

### Required agent progress-report format

```text
Milestone:
Implemented files:
Commands executed:
Test summary (passed/failed/skipped):
Evidence / artifacts:
Risks or unresolved issues:
Next planned milestone:
```

---

## 17. References and Implementation Documentation

- Sony CLEFIA specification (primary): https://www.sony.co.jp/en/Products/cryptography/clefia/download/data/clefia-spec-1.0.pdf
- RFC 6114 (algorithm, test and intermediate values): https://www.rfc-editor.org/rfc/rfc6114.html
- Original design paper (Shirai et al., 2007), supplied with the capstone.
- Gea (2022), original application article, supplied with the capstone.
- FastAPI documentation: https://fastapi.tiangolo.com/
- Vercel FastAPI documentation: https://vercel.com/docs/frameworks/backend/fastapi
- Vercel Python runtime announcement (2026-10-15): https://vercel.com/changelog/python-on-vercel-is-now-generally-available
- Academic-only warning: reversible encryption of passwords is deliberately not a recommended production practice; no real credentials may be used.
- NIST SP 800-38A (CTR mode background): https://csrc.nist.gov/pubs/sp/800/38/a/final

**Provenance statement:** The research problem and source hierarchy follow the supplied capstone materials. The authenticated record format, detailed acceptance tests, repository layout, and agent milestone gates are **proposed engineering design decisions** added to make the project implementable and auditable.


---

## 18. Existing Implementation Change Request — CR-001

This revised PRD supersedes the old `PRD.md` requirements for credential storage. The attached progress log reports M0–M7 completed (46 tests passed) before this change. **Do not recreate the repository or rewrite the CLEFIA primitive.** Continue from the current working tree and use the separate `CLEFIA128_CREDENTIALS_AGENT_CHANGE_REQUEST.md` for exact steps, migration caveats, and new acceptance tests. Preserve official vector `de2bf2fd9b74aacdf1298555459494fd` and the previous mathematical experiment results unless a rerun demonstrates different actual measurements. Live PostgreSQL and Vercel remain unverified until configured.
