# Product Requirements Document (PRD)
## CLEFIA-128 Educational Web Application — Indonesian UI, CLEFIA-Only Record Encryption

| Item | Decision |
|---|---|
| Document version | **2.0 — Scope reset / CR-002** |
| Date | 2026-11-17 |
| PRD language | English (instructions for the coding agent) |
| Application interface language | **Bahasa Indonesia (id-ID), mandatory** |
| Project type | Mathematics of Cryptography capstone; educational prototype |
| Existing codebase | Continue the implementation described in `docs/agent_progress.md`; **do not rebuild from scratch** |
| Core cryptographic algorithm | **CLEFIA-128**, implemented in pure Python |
| Variable-length text mode | **CLEFIA-128 in CTR mode**, without HMAC/MAC |
| Authentication data | Synthetic **username and password both reversibly encrypted with CLEFIA** |
| Username lookup strategy | **Approach A: decrypt-and-scan** (no blind index or deterministic ciphertext lookup) |
| Additional encrypted field | **Profile Note is mandatory and must be preserved** |
| Backend / templates | Python, FastAPI, Jinja2, HTML/CSS |
| Database / migrations | PostgreSQL, SQLAlchemy, Alembic |
| Deployment target | Vercel, subject to access/credential availability |
| Removed from new architecture | **HMAC-SHA-256, HMAC authentication tags, HMAC blind index, Argon2id and password hashing** |

> **Agent instructions:** This document supersedes `CLEFIA128_AI_Agent_PRD_v1_1_Credentials.md`, `CLEFIA128_CREDENTIALS_AGENT_CHANGE_REQUEST.md` (CR-001), and the original PRD wherever they conflict. They are historical references, **not active requirements**. Read the existing repository and `docs/agent_progress.md` before editing. Implement **CR-002 as a refactor**, preserving verified CLEFIA components, existing tests where still applicable, Profile Note, and the research results. Do not falsely report cloud integration or successful tests that you have not actually executed.

---

## 1. Executive Summary

Create a small **Indonesian-language academic web application** that demonstrates the original Sony **CLEFIA-128** cipher on simulated user records. The application shall encrypt **username, password, and Profile Note** with the same verified CLEFIA-128 block-cipher implementation, using CTR mode to handle strings of variable length.

This capstone reproduces the **application concept** in Gea (2022) with different software: **Python/FastAPI** rather than the technology presented in the reference application. The project must prioritize mathematical transparency, correctness against published test vectors, and reproducible avalanche/SAC/benchmark experiments.

**Simplification decision:** Remove HMAC for both data integrity and username lookup. Remove Argon2id and all password-hash functionality. Login shall find accounts through a **linear scan of encrypted usernames**, decrypt the candidate username of each record, and compare it to the submitted username. Once a matching account is found, decrypt its stored password temporarily in server memory and compare it with the submitted password.

**Important and non-negotiable limitation:** CTR encryption **without a MAC is malleable and does not authenticate ciphertext**. It cannot reliably detect changes to encrypted username/password/note values or provide the confidentiality/integrity guarantees of a production credential store. Reversible encrypted passwords are likewise unsuitable for real user authentication. This is a **controlled educational demonstration only**. No real accounts, real passwords, personal records, or production security claims are permitted. The UI must prominently state this limitation in Bahasa Indonesia.

### 1.1 Required features

1. Account registration using a synthetic username and password; both fields are stored **only** as CLEFIA ciphertext and nonces.
2. Login via **Approach A: decrypt all stored usernames until an exact canonical match is found**, followed by CLEFIA decryption of the matching account's password.
3. Logged-in dashboard showing a masked/recovered username, the encryption status of each field, and **ciphertext + nonce** for the authenticated owner's fields; **never display the decrypted password**.
4. **Profile Note must remain functional**: create, edit, encrypt, store, decrypt, and display only to the signed-in owner.
5. Password change for a demonstration account, generating a new nonce; no password hash.
6. A mathematics page explaining finite fields, substitution, Feistel rounds, key scheduling, the block test vector, and optional safe visualization of **public fixed test vectors**.
7. Experiment results page with **avalanche effect, empirical SAC, and benchmark plots**, localized into Bahasa Indonesia.
8. Health endpoint, existing protections around sessions/forms, and reproducible tests.

### 1.2 Explicit non-goals

- Real-world authentication and real password storage.
- HMAC, MAC tags, blind indices, Argon2id, password hashing, or an added cryptographic algorithm for record confidentiality/integrity.
- Comparing CLEFIA against AES, RSA, SHA, C, JavaScript, or another cipher/language.
- Building new CLEFIA-192/256 implementations, mobile apps, email/password reset, or an administrative identity platform.
- Proving full cryptographic security from avalanche statistics.
- Running expensive experiments on every web request.
- Automatically deleting or migrating existing non-demo data.

---

## 2. Prior Progress: What to Preserve and What to Replace

The supplied `agent_progress.md` reports that milestones M0–M7 have been completed with **46 tests passing at the last recorded run**. This is historical agent-reported evidence; the current agent must rerun tests after its changes.

| Existing milestone / module | Required action |
|---|---|
| M0 repository, `uv`, CI, FastAPI bootstrap | **Preserve** |
| M1 `GF(2^8)`, S-boxes, F-functions, GFN, DoubleSwap | **Preserve exactly** |
| M2 key schedule, encrypt/decrypt block, trace, official vectors | **Preserve exactly** |
| M3 CTR-mode implementation | **Reuse CTR logic**; strip HMAC and authenticated envelopes |
| M4 users, authentication, Alembic | **Refactor** to encrypted credentials and scan-based login |
| M5 Jinja2 routes/UI, session controls | **Preserve flow**, update fields and translate every user-facing string |
| M5 Profile Note `/profile` | **Must preserve**, update to CLEFIA-CTR without MAC |
| M6 avalanche, SAC, benchmark and plots | **Preserve algorithms/data**, translate plots/HTML labels |
| M7 Vercel, QA, README, deployment config | **Preserve**, revise environment/docs/tests |

**Former tests that must be replaced rather than maintained unchanged:** HMAC-tag tamper rejection, HMAC-associated-data binding, blind-index lookup, and Argon2id password-hash assertions. Their removal is intentional; do not keep misleading tests that assert the old security properties.

**Previously unresolved external dependencies:** the progress log states that **live PostgreSQL** and **live Vercel deployment** were not verified. Preserve those as pending until tested with actual services; do not report them as complete from SQLite or offline SQL generation alone.

---

## 3. Mathematical Specification and Correctness Gates

### 3.1 Raw block cipher

- CLEFIA with a **128-bit block** and a **128-bit key**; 18 encryption rounds.
- Four 32-bit branches in a generalized Feistel network (GFN).
- Two F-functions (`F0`, `F1`), 8-bit S-boxes (`S0`, `S1`), two 4 × 4 diffusion matrices (`M0`, `M1`), and correct whitening positions.
- `GF(2^8)` multiplication modulo `x^8 + x^4 + x^3 + x^2 + 1` (`0x11D`).
- Key schedule with GFN4,12, DoubleSwap, 60 constants, 4 whitening words, 36 round-key words.
- Preserve the implementation's existing byte order and round traces, verified against Sony/RFC 6114; do **not** modify mathematical primitives for web convenience.

The block operation satisfies:

```text
E_K : {0,1}^128 -> {0,1}^128
D_K(E_K(P)) = P
```

**Mandatory official test vector (release blocker):**

```text
KEY        = ffeeddccbbaa99887766554433221100
PLAINTEXT  = 000102030405060708090a0b0c0d0e0f
CIPHERTEXT = de2bf2fd9b74aacdf1298555459494fd
```

Also retain intermediate-value tests (including key schedule and rounds) and at least **1,000 seeded random block encrypt/decrypt round-trips**.

### 3.2 Variable-length input: CLEFIA-CTR only

The web app must not use the 128-bit block cipher directly on arbitrary-length text. Reuse the existing CTR implementation. For each field:

```text
nonce = 12 cryptographically random bytes
counter_block_i = nonce || uint32_be(1 + i)  # keep existing counter start at 1
keystream_i = CLEFIA_Encrypt_Block(K, counter_block_i)
ciphertext_i = plaintext_i XOR keystream_i[:len(plaintext_i)]
plaintext_i = ciphertext_i XOR keystream_i[:len(ciphertext_i)]
```

- Encode strings to **UTF-8 bytes** before encryption; decode UTF-8 strictly after decryption.
- Exactly **one 128-bit encryption key**, loaded from server-side configuration, for this simplified demonstrator.
- Generate a **new 96-bit nonce for every encryption of every field**. Never reuse a nonce with the same key, including across users and between username/password/note.
- Preserve CTR's **32-bit big-endian counter starting at 1** as documented in the earlier PRD, unless existing code uses a different verified convention; document and test the exact convention before changes.
- Reject message lengths that would cause counter overflow or exceed configured input bounds.
- Use a globally unique `(key_id, nonce)` constraint in a common encrypted-fields table, or an equivalently enforced central nonce registry; handle rare collision retries transactionally.
- No HMAC/CRC/checksum should be presented as cryptographic integrity protection. Nonce uniqueness does **not** prevent ciphertext modification.
- Do not use ECB, a fixed nonce, IV reuse, deterministic encryption, or custom unreviewed padding.

**Storage representation:** Base64 or hexadecimal is display encoding only, not encryption. Ciphertext is binary data (`BYTEA`) in PostgreSQL.

### 3.3 Minimal record-encryption API

An agent may adapt existing names, but the public behavior must be equivalent to:

```python
@dataclass(frozen=True)
class EncryptedField:
    version: int
    key_id: str
    nonce: bytes      # exactly 12 bytes
    ciphertext: bytes # any supported length, may be empty for the note only

class ClefiaRecordService:
    def encrypt_text(self, plaintext: str, *, key_id: str) -> EncryptedField: ...
    def decrypt_text(self, encrypted: EncryptedField) -> str: ...
```

- **No `tag`, `auth_tag`, `compute_record_mac`, `build_mac_input`, or `AuthenticationError` semantics** in the new envelope. Replace with appropriately named format/decode errors.
- Validate envelope version, key ID, nonce length, stored ciphertext length, and UTF-8 decoding; reject structurally invalid records.
- Do **not** imply that validation detects intentional modification of valid CTR ciphertext. It cannot.
- Keep the primitive-layer imports independent of FastAPI, SQLAlchemy, and web sessions.

### 3.4 Mathematical experiments (must be retained)

Experiments must run on the **raw CLEFIA block primitive**, not randomized CTR record ciphertext, to prevent nonce variation from distorting mathematical measurements.

**Avalanche effect:** Flip each of the 128 plaintext bits independently; also measure single-bit key changes separately.

```text
HD(A, B)  = popcount(A XOR B)
AE_i      = HD(E_K(P), E_K(P XOR 2^i)) / 128
AE_mean   = average over bits and seeded input pairs
```

**Empirical Strict Avalanche Criterion:** estimate the **128 × 128** matrix where entry `(i, j)` is the observed probability that output bit `j` changes after input bit `i` flips; display deviation from 0.5 and sampling uncertainty.

**Benchmark:** compare key expansion, encryption and decryption; clearly separate operations **with** and **without** key expansion, report iterations, warm-up, seed if applicable, operating system, Python version, CPU if available, units, and summary statistics. Preserve prior CSV/JSON artifacts; regenerate if test environment changes and label new runs honestly.

---

## 4. Core Functional Requirements

| ID | Requirement | Priority | Acceptance criterion |
|---|---|---|---|
| FR-01 | Register simulated account | P0 | Username and password encrypted with CLEFIA-CTR and distinct random nonces before DB insert |
| FR-02 | Scan-based username lookup | P0 | Full scan decrypts encrypted usernames; no HMAC/index/username plaintext column |
| FR-03 | Login | P0 | Find matching decrypted username, then decrypt password and compare; wrong credentials fail |
| FR-04 | Username uniqueness | P0 | Duplicate canonical username rejected through decrypt-and-scan at registration |
| FR-05 | Profile Note | P0 | Existing note creation/update/decryption survives; encrypted CTR storage; owner-only |
| FR-06 | Change demonstration password | P1 | Reencrypt with fresh nonce; old password fails and new password works |
| FR-07 | Owner-only ciphertext viewer | P1 | Shows username/password/note ciphertext and nonce in hex; never reveals password plaintext/key |
| FR-08 | Mathematical explanation | P0 | Indonesian explanation of CLEFIA stages, official vector and finite-field operations |
| FR-09 | Experimental results | P0 | Avalanche, SAC and benchmark screens render Indonesian text and plots |
| FR-10 | Session handling | P0 | Existing session renewal, revocation, CSRF, cookie protections preserved |
| FR-11 | Small-data guardrail | P0 | Demo user cap and pagination/bounded scan logic; no unbounded public account creation |
| FR-12 | Complete Indonesian UI | P0 | All user-visible text, errors, charts, labels, metadata explanations localized |
| FR-13 | Deployment readiness | P1 | Runs locally; Vercel configuration and live PostgreSQL instructions documented |

### 4.1 Registration — exact required flow

1. Receive a **synthetic** username and password through a CSRF-protected form.
2. Validate lengths, encoding, acceptable characters, and account cap; reject real credential use in UI guidance.
3. Canonicalize username consistently: **Unicode NFKC**, `strip()` surrounding whitespace, then `casefold()`; reject an empty result. Encrypt and store the **canonical username** so duplicate checks are deterministic.
4. Load the existing encrypted `username` records through a **bounded database query**, decrypt each username using CLEFIA, and compare with the canonical candidate. Do not add a plaintext index, HMAC blind index, or deterministic-nonce shortcut.
5. If no duplicate exists, create a UUID user ID; encrypt the canonical username and the password into **two separate encrypted fields** with different fresh nonces.
6. Insert user and both encrypted fields in **one database transaction**. A partial failure must roll back everything.
7. Handle concurrent registrations safely for the demo: serialize registration/check-and-insert operations using a documented database-level coordination mechanism (e.g., PostgreSQL transaction-level advisory lock for the registration critical section). Without an index, application-only duplicate checking is race-prone. SQLite fallback tests may use serialized transactions.
8. Return an Indonesian success message and redirect to login. No plaintext username/password in DB columns or logs.

### 4.2 Login — Approach A (required)

```python
async def authenticate_demo_user(input_username: str, input_password: str):
    candidate = canonicalize_username(input_username)
    # This is pseudocode. Use bounded ORM queries and the existing sync/async style.
    for user, username_field in list_all_demo_usernames_in_stable_order():
        stored_name = decrypt_clefia_ctr_to_utf8(username_field)
        if stored_name == candidate:
            password_field = load_encrypted_field(user.id, "password")
            stored_password = decrypt_clefia_ctr_to_utf8(password_field)
            if secrets.compare_digest(stored_password.encode("utf-8"),
                                      input_password.encode("utf-8")):
                return user
            return None
    return None
```

Detailed rules:

- The application **MUST actually decrypt stored usernames during login**; do not use the prior `username_lookup`, password hash, or plaintext username.
- Comparisons use normalized/canonical usernames; passwords are **case-sensitive and never normalized**.
- The password is decrypted **temporarily in server memory** only. Do not persist, cache, log, return, show, or expose it through an API.
- Use `secrets.compare_digest` for comparison. This is not HMAC and does not add a password-hashing algorithm.
- Return the same user-facing Indonesian message for unknown username and incorrect password: **“Nama pengguna atau kata sandi salah.”**
- Preserve login rate limiting and session creation only on successful authentication.
- If a stored encrypted field is malformed or fails UTF-8 decode, fail safely with a generic error, log a record ID **only**, and do not show raw ciphertext or credentials to anonymous users.
- The decrypt-and-scan algorithm costs **O(n)** username decryptions per login and duplicate check. This is a deliberate educational trade-off and requires small synthetic datasets and rate limits.

### 4.3 Profile Note (mandatory)

- Existing `/profile` GET/POST workflow and templates must remain available.
- A signed-in user can create, edit, encrypt, persist, decrypt, and view **their own** note.
- The note is encrypted via the same `ClefiaRecordService` (CTR, no HMAC), with a fresh nonce per save.
- Support UTF-8, punctuation, Indonesian text, empty note and a multi-block note, with explicit maximum input length.
- A different account must not be able to access or modify the note; enforce owner checks in the database query, not just the UI.
- No generic public decryption endpoint and no password plaintext display.

### 4.4 Credential ciphertext display

Provide an authenticated `/credentials` page, or a clearly separated dashboard section:

| Indonesian label | Contents |
|---|---|
| `Data` | `Nama pengguna`, `Kata sandi`, `Catatan profil` |
| `Algoritma` | `CLEFIA-128` |
| `Mode operasi` | `CTR` |
| `Ciphertext (heksadesimal)` | Hex representation of stored ciphertext |
| `Nonce (heksadesimal)` | Hex representation of 12-byte nonce |
| `Panjang data (byte)` | Length of ciphertext in bytes |
| `Status penyimpanan` | `Terenkripsi` / `Belum tersedia` |

Do not show or offer a button to show the decrypted password. A signed-in user's username and note may be displayed in plaintext when needed for normal app functionality.

---

## 5. Proposed Persistence Schema and Migration Strategy

### 5.1 Minimal data model

Preferred generic schema (adapt the existing `ProfileEncryptedField` table if feasible):

```text
users
  id                      UUID PRIMARY KEY
  created_at              TIMESTAMPTZ NOT NULL
  # no username plaintext, no username_lookup, no password_hash

encrypted_fields
  id                      UUID PRIMARY KEY
  owner_id                UUID NOT NULL REFERENCES users(id)
  field_name              VARCHAR NOT NULL  # username | password | profile_note
  algorithm_version       SMALLINT NOT NULL
  key_id                  VARCHAR NOT NULL
  nonce                   BYTEA NOT NULL    # 12 bytes
  ciphertext              BYTEA NOT NULL    # variable length
  updated_at              TIMESTAMPTZ NOT NULL
  UNIQUE(owner_id, field_name)
  UNIQUE(key_id, nonce)                  # global nonce uniqueness for shared key

user_sessions
  # preserve existing session lifecycle / revocation design

auth_rate_limits
  # preserve existing login abuse throttling
```

- Index `encrypted_fields(owner_id, field_name)` for owner-scoped reads; this is a **normal database index**, not a keyed blind username index.
- For username scan, query only `users.id` plus the encrypted fields named `username`; do not decrypt unrelated notes/passwords during scanning.
- Add constraints/validation for exact nonce size and known field names; use parameterized SQLAlchemy queries.
- Keep DB credentials and encryption keys in environment variables, never in the frontend.
- One shared random key per application is acceptable for **this demo**, with strictly unique nonces. Do not export the key to clients.

### 5.2 Legacy data and migration

The current progress log describes an older database using Argon2id, HMAC-authenticated notes, and `ProfileEncryptedField`. **Do not assume those data can be migrated automatically.**

1. Inspect the existing Alembic history and actual schema first; create a **new additive migration** instead of rewriting existing deployed migrations.
2. Back up any existing data before schema changes. **Never drop real or shared data automatically.**
3. Existing Argon2id hashes **cannot be decrypted** into CLEFIA passwords. Old demo accounts must be re-registered with new synthetic credentials, or their passwords re-entered by the operator under an explicitly approved migration flow.
4. Existing notes may be recoverable **only if the old legitimate encryption/MAC keys are available**. If preserving demo notes is necessary, implement a one-time **local/offline** operator-controlled conversion after authorization: authenticate/decrypt with the old scheme and reencrypt with new CTR nonces; never put those keys into a public endpoint or log plaintext.
5. For a disposable demo database, provide a documented **opt-in reset command**, with an explicit confirmation flag. Do not execute destructive resets on the user's behalf without approval.
6. Eliminate obsolete HMAC columns/configuration for the **new schema** only after migrations and tests; document any legacy columns retained for migration compatibility.
7. Update `scripts/verify_postgres.py` and database test fixtures to match the new records and **avoid HMAC tamper-rejection assertions**.

### 5.3 Environment variables

```dotenv
DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME
CLEFIA_ENC_KEY_HEX=<32_HEX_CHAR_128_BIT_KEY>
CLEFIA_KEY_ID=demo-v2
SESSION_SECRET_KEY=<LONG_RANDOM_SECRET_IF_EXISTING_SESSION_SYSTEM_REQUIRES_IT>
APP_ENV=development
DEMO_MAX_USERS=100
```

- Remove `CLEFIA_MAC_KEY_HEX`, `USERNAME_INDEX_KEY_HEX`, Argon2 configuration, and obsolete settings from `.env.example` and the active application.
- `SESSION_SECRET_KEY` is **session infrastructure**, not an HMAC mechanism for record encryption; preserve whichever existing session security implementation is appropriate without building a new custom cryptographic protocol.
- Validate encryption key is **exactly 16 bytes**. Fail at startup rather than generating an untracked fallback key.
- Never expose secrets in rendered templates, source control, client JavaScript, exceptions, screenshots, logs, or generated experiment artifacts.

---

## 6. Indonesian-Only User Interface and Content Requirements

### 6.1 Localization scope

Every text **visible to the app user** must be in **Bahasa Indonesia**:

- Landing page, navigation, footer, site title, warnings, project overview, and instructional text.
- Registration, login, logout, dashboard, profile note, ciphertext metadata, password change, mathematics, experiments, and error pages.
- Buttons, labels, placeholders, validation messages, alerts, empty states, pagination, tooltips, success messages, and confirmation dialogs.
- Status labels, accessible `aria-label`, image `alt`, and form accessibility explanations.
- Human-readable API error `detail` strings returned to the browser, including `400`, `401`, `403`, `404`, `422`, `429`, and `500` (generic server error).
- Plot titles, axis labels, legends, captions, table headers, and any chart presented on `/experiments`.
- Downloaded report **titles and explanatory headings** linked directly from app UI, where under project control.

**Technical exception:** internal route paths, database identifiers, Python symbol names, API JSON keys, file names and standard algorithm names (CLEFIA, CTR, GFN, S-box, Hamming distance) may remain in English; their explanations must be Indonesian. The PRD and technical code comments may remain English.

Use `<html lang="id">`, UTF-8 templates, and consistent Indonesian terminology. Do **not** merely translate the landing page; localization is a release-blocking cross-cutting requirement.

### 6.2 Required Indonesian copy

| Component | Required text (or close natural Indonesian equivalent) |
|---|---|
| Product title | `Demonstrasi Enkripsi CLEFIA-128` |
| Academic warning banner | `Aplikasi ini hanya untuk demonstrasi akademis. Gunakan nama pengguna dan kata sandi simulasi. Jangan gunakan kredensial asli.` |
| Navigation | `Beranda`, `Daftar`, `Masuk`, `Dasbor`, `Catatan Profil`, `Data Terenkripsi`, `Matematika CLEFIA`, `Eksperimen`, `Keluar` |
| Register form | `Nama pengguna`, `Kata sandi`, `Konfirmasi kata sandi`, `Buat Akun Simulasi` |
| Login form | `Masuk ke Akun`, `Nama pengguna`, `Kata sandi`, `Masuk` |
| Duplicate registration | `Nama pengguna sudah digunakan.` |
| Invalid login | `Nama pengguna atau kata sandi salah.` |
| Logout success | `Anda telah keluar dari akun.` |
| Note editor | `Catatan Profil`, `Isi catatan`, `Simpan Catatan`, `Lihat Hasil Dekripsi` |
| Saved note | `Catatan berhasil disimpan dalam bentuk terenkripsi.` |
| Password update | `Ubah Kata Sandi Simulasi`, `Kata sandi baru`, `Kata sandi berhasil diperbarui.` |
| Status | `Terenkripsi`, `Belum tersedia`, `Berhasil`, `Gagal` |
| Core mathematics | `Struktur Jaringan Feistel`, `Substitusi S-box`, `Perkalian pada GF(2⁸)`, `Penjadwalan Kunci`, `Putaran Enkripsi` |
| Experiments | `Efek Avalanche`, `Kriteria Avalanche Ketat (SAC)`, `Perbandingan Waktu Eksekusi`, `Jarak Hamming`, `Frekuensi`, `Waktu (mikrodetik)` |
| General error | `Terjadi kesalahan. Silakan coba lagi.` |
| Rate limited | `Terlalu banyak percobaan. Coba lagi nanti.` |
| Page not found | `Halaman tidak ditemukan.` |
| Access denied | `Anda tidak memiliki izin untuk mengakses halaman ini.` |

Use proper Indonesian spelling and terminology. Use `nama pengguna` instead of untranslated `username` in visible UI; the technical code may still use `username`.

### 6.3 Presentation / usability rules

- Keep current Jinja2 templates and CSS as the base; improve only where required.
- Make form error messages human-readable and associated with fields.
- Mobile-friendly presentation is sufficient; do not add a heavy frontend framework.
- Provide clearly marked **simulation-only** sample usernames/passwords in documentation (not a default shared production password).
- Never show raw errors or a Python stack trace on browser pages.
- Pages with authentication data should use appropriate `Cache-Control: no-store`; keep cookie protections and CSRF.
- Plot image paths can remain as they are; ensure any **embedded chart text** is translated by regenerating graphs where necessary.
- Include a visible explanation (in Indonesian) that the demo does **not** validate ciphertext integrity after HMAC removal.

---

## 7. Routes and Access Control

Preserve working route paths unless a change is essential.

| Method / route | Function (shown in Indonesian) | Access |
|---|---|---|
| `GET /` | `Beranda` | Public |
| `GET /register` | `Daftar akun simulasi` | Public |
| `POST /register` | Register, scan for canonical duplicates, encrypt fields | Public + CSRF + rate-limited |
| `GET /login` | `Masuk` | Public |
| `POST /login` | Scan/decrypt usernames, decrypt matching password | Public + CSRF + rate-limited |
| `POST /logout` | `Keluar` and revoke session | Signed in + CSRF |
| `GET /dashboard` | `Dasbor` and encryption summary | Signed in |
| `GET /credentials` | `Data Terenkripsi` (owner-only ciphertext/nonce viewer) | Signed in |
| `GET /profile` | `Catatan Profil` | Signed in |
| `POST /profile` | Save CLEFIA-encrypted note | Signed in + CSRF |
| `GET /change-password` | `Ubah Kata Sandi Simulasi` | Signed in |
| `POST /change-password` | Reencrypt password with new nonce | Signed in + CSRF |
| `GET /math` | `Matematika CLEFIA` | Public, public test data only |
| `GET /experiments` | `Eksperimen` | Public, precomputed results only |
| `GET /experiments/plots/{filename}` | Graph images (localized labels) | Public, strict allowlist |
| `GET /health` | Health status | Public (minimal metadata) |

**No public API** exposing a server-key encryption/decryption oracle, raw credentials, arbitrary ciphertext decryption, or the CLEFIA encryption key.

**Authorization:** Protect note viewing, ciphertext metadata, and password updates by matching the current session's `user_id` to database owner ID. Retain the existing CSRF, session revocation, request throttling, and security headers. These are general web safety controls, not extra ciphers to be analyzed in the capstone.

---

## 8. Agent Refactoring Plan — CR-002

**Implement in this order.** Each gate must pass before moving on; no destructive database operations without explicit approval.

### CR-002.0 — Repository and dependency audit

- Read active `PRD.md`, `docs/agent_progress.md`, `docs/architecture.md`, `docs/threat_model.md`, `pyproject.toml`, `src/clefia/record_crypto.py`, `src/web/auth.py`, models, routes, migrations, templates, all tests.
- Enumerate every HMAC / blind-index / Argon2 / `password_hash` / `auth_tag` reference **before editing**.
- Confirm the existing CTR nonce layout and 32-bit counter convention; write down any discrepancy with the previous PRD.
- Capture baseline `uv run pytest -v` and `uv run ruff check .` results. Do not claim the previous 46 tests still pass without running them.

**Gate:** audit notes in `docs/agent_progress.md`; exact migration/compatibility plan recorded.

### CR-002.1 — Record crypto simplification

- Keep `encrypt_block`, `decrypt_block`, `key_schedule_128` and mathematical primitives unchanged.
- Retain CTR keystream logic. Replace HMAC-aware record envelope with a **nonce + ciphertext + version/key-id** envelope.
- Remove unused HMAC/MAC helpers, `auth_tag` processing, and authentication claims from service/docstrings.
- Add unit tests for deterministic block vectors, variable-length CTR round trips, nonce uniqueness and overflow/UTF-8 errors.
- Replace MAC tamper-rejection tests with **documented negative tests**: malformed envelopes fail structural validation, but valid-looking modified ciphertext is **not guaranteed to be detected**.

**Gate:** raw CLEFIA M1–M2 tests remain unchanged/passing, and new record-crypto tests pass.

### CR-002.2 — Database and login redesign

- Build or adapt `encrypted_fields` table and Alembic migration, with username/password/note records and global unique nonces.
- Remove Argon2id password hasher and username HMAC blind-index logic from application code.
- Implement `canonicalize_username()` and **decrypt-and-scan login** with duplicate checking and registration concurrency guard.
- Preserve sessions, CSRF, rate limits, and owner scope.
- Create self-contained SQLite test fixtures; separately verify PostgreSQL DDL. No silent destructive reset.
- Reuse existing profile-note data model when possible; protect its owner ID.

**Gate:** registration/login/duplicate/password-change/note/access-control tests pass locally.

### CR-002.3 — Indonesian localization (all app UI)

- Inventory all Jinja templates and front-end-visible strings; translate all of them.
- Translate UI explanations of mathematical formulas, result charts, and captions; preserve symbols and numeric outputs.
- Implement centralized Indonesian error handling for request validation/HTTP errors and all error pages.
- Set `lang="id"`, accessible labels, meaningful alt text, and localized empty states.
- Ensure no default English messages from FastAPI/Pydantic leak directly into visible HTML/API response messages.

**Gate:** localization coverage tests assert known Indonesian strings and verify English placeholder phrases do not remain on rendered pages/plots.

### CR-002.4 — Preserve/reinforce mathematical learning features

- Confirm `/math` shows the published CLEFIA vector and explains each mathematical building block in Indonesian.
- Keep avalanche, SAC, and benchmark scripts unchanged in mathematical computation; regenerate plots with Indonesian titles/labels.
- Optionally show a **fixed, public** encryption trace across 18 rounds, with no application secret key or user password involved.
- Do not change historical experiment values without rerunning experiments.

**Gate:** original scientific tests pass; chart and math page localization tests pass.

### CR-002.5 — Documentation, regression, and deployment

- Rewrite `README.md`, `docs/architecture.md`, and `docs/threat_model.md` for this v2 scope: no MAC integrity, scan-based lookup, reversible passwords, synthetic-only use.
- Remove obsolete config/dependencies, regenerate `uv.lock`, keep historical notes in progress log.
- Run `uv lock --check`, `uv run ruff check .`, `uv run pytest -v` and local FastAPI smoke tests.
- Run `alembic upgrade head --sql` and local SQLite integration; run **live PostgreSQL** only when a service/URL is available.
- Do not mark **Vercel live deployment** validated without actually deploying and testing the URL.

**Gate:** all v2 acceptance tests pass; artifacts and outstanding blockers recorded.

---

## 9. Required Test and Acceptance Matrix

| Test ID | Required verification | Pass criterion |
|---|---|---|
| T-001 | Official CLEFIA-128 block test vector | Exact `de2bf2fd9b74aacdf1298555459494fd` |
| T-002 | S-box/round keys/trace and GF arithmetic | RFC 6114 intermediate values match |
| T-003 | Seeded raw cipher round trips | At least 1,000 pass |
| T-004 | CTR bytes/UTF-8/multi-block/empty note | Plaintext recovered exactly |
| T-005 | Nonce uniqueness across **all field types** | Unique `(key_id, nonce)`; forced collision handled |
| T-006 | Username/password encrypted persistence | No plaintext credentials, `password_hash`, `auth_tag`, `username_lookup` |
| T-007 | Decrypt-and-scan login | Correct demo login, wrong password, unknown username |
| T-008 | Duplicate username, canonicalization | `NFKC + strip + casefold` rejects duplicates |
| T-009 | Concurrency / transaction atomicity | No duplicate canonical username under concurrent registration |
| T-010 | Password change | Fresh nonce; old rejected, new accepted; no password display |
| T-011 | Profile Note preserved | Owner can save/update/read; other user cannot |
| T-012 | Format errors and no integrity claims | Malformed data handled; documented CTR tamper limitation |
| T-013 | CSRF / sessions / throttling | Existing protections and denial cases pass |
| T-014 | Indonesian UI copy | All visible HTML, errors, charts, labels, alt text localized |
| T-015 | Mathematical experiments | Avalanche, SAC, benchmark reproducible and correctly labeled |
| T-016 | Local FastAPI smoke | Full register -> login -> note -> logout flow passes |
| T-017 | PostgreSQL migration | SQL generation passes; live test only with real PostgreSQL |
| T-018 | Vercel deployment | HTTPS smoke test passes **only when actually deployed** |
| T-019 | No forbidden legacy dependencies | No active HMAC, blind-index, Argon2id, password-hash code/config |
| T-020 | Secret hygiene | No encryption key, password plaintext, decrypted password in logs or UI |

### 9.1 Localization test examples

At minimum, an automated route test should assert:

```python
assert 'lang="id"' in response.text
assert "Nama pengguna" in response.text
assert "Kata sandi" in response.text
assert "Demonstrasi Enkripsi CLEFIA-128" in response.text
```

Add route-specific checks for `Catatan Profil`, `Matematika CLEFIA`, `Efek Avalanche`, and generic localized errors. Confirm the static PNG charts' embedded labels are Indonesian by reviewing newly generated plots visually; string-only HTML tests cannot guarantee image localization.

### 9.2 Core-regression command examples

```bash
uv sync --extra dev
uv lock --check
uv run ruff check .
uv run pytest -v
uv run python -m experiments.avalanche --seed 20261115 --samples 64
uv run python -m experiments.sac --seed 20261115 --samples 64
uv run python -m experiments.benchmark --seed 20261115
```

Do **not** assert that benchmarks are universally fixed across computers. Record environment metadata.

---

## 10. UI Layout and Demo Walkthrough

### 10.1 Minimal page map

```text
Beranda
 ├─ Daftar  -> simpan username/password sebagai ciphertext CLEFIA
 ├─ Masuk   -> dekripsi username satu per satu -> cocokkan -> dekripsi password
 ├─ Dasbor [login]
 │   ├─ Data Terenkripsi -> tampilkan ciphertext + nonce milik sendiri
 │   ├─ Catatan Profil   -> enkripsi/dekripsi CLEFIA untuk teks panjang
 │   └─ Ubah Kata Sandi -> ciphertext/nonce baru
 ├─ Matematika CLEFIA -> GFN, GF(2^8), S-box, whitening, key schedule
 └─ Eksperimen -> efek avalanche, SAC, benchmark (grafik Bahasa Indonesia)
```

### 10.2 Lecturer demonstration, in order

1. Show the academic-only Indonesian warning and project explanation.
2. On `/math`, demonstrate official public test vector and mathematical components.
3. Register a test account with synthetic username/password; show only **ciphertext + distinct nonces** in DB or owner screen.
4. Log out and log back in; explain **linear decrypt-and-scan** (no HMAC lookup index).
5. Enter an Indonesian Profile Note over 16 bytes, save and decrypt it as the owner.
6. Show login fails with the wrong password and that another user cannot read the note.
7. Show `/experiments` avalanche/SAC/benchmark charts with Indonesian labels.
8. Explain limitations: **no integrity verification in CTR-only format, reversible passwords, O(n) login**, and why deployment is demo-only.
9. Show the test suite and clearly differentiate local tests from unverified PostgreSQL/Vercel steps.

---

## 11. Risks, Limitations, and Non-negotiable Warnings

| Risk | Required mitigation / disclosure |
|---|---|
| CTR malleability; no HMAC | Clearly state ciphertext manipulation is **not reliably detectable**; never claim authenticated encryption |
| Reversible password storage | Synthetic passwords only, demo-only warning; no real credential collection |
| Decrypt-and-scan complexity O(n) | Limit accounts (default `DEMO_MAX_USERS=100`), throttle login, bound query size |
| Canonical duplicate race | Database-side critical-section coordination and transaction atomicity |
| Nonce reuse across fields | Global unique `(key_id, nonce)` or equivalent registry; collision retry |
| Key leakage | Server-side env only; fail-closed startup; no secret-bearing logs or frontend code |
| Bad ciphertext/UTF-8 | Safe generic error, no tracebacks to users, no invented integrity guarantee |
| Legacy Argon2 accounts | Cannot recover passwords; explicit demo reset/re-registration with consent |
| Old authenticated note data | Operator-controlled migration only if old keys available, no unaudited automatic rewrite |
| Public deployment | Prefer controlled access, synthetic sample accounts, HTTPS and retained web controls |
| Misinterpretation of avalanche result | Explain that ~50% empirical avalanche is **not proof of security** |

### Required persistent disclaimer on the website

> **Aplikasi ini hanya untuk demonstrasi akademis algoritma CLEFIA-128. Gunakan data simulasi, bukan nama pengguna atau kata sandi asli. Enkripsi dalam mode CTR tanpa pemeriksaan autentikasi tidak dapat menjamin bahwa data terenkripsi tidak diubah.**

The same meaning must appear in `README.md` and `docs/threat_model.md`.

---

## 12. Completion / Definition of Done

**Do not close CR-002** until all of the following hold:

- [ ] Core CLEFIA block implementation and official vectors still pass unmodified.
- [ ] Username and password are encrypted with CLEFIA only; no Argon2id or HMAC encryption wrapper/index.
- [ ] Login truly scans and decrypts usernames, then decrypts the matching password.
- [ ] No plaintext username/password stored in database; no password plaintext displayed.
- [ ] Global unique nonces enforced, and a new nonce is used for every field update.
- [ ] **Profile Note is retained and working**, including long Indonesian UTF-8 text.
- [ ] Registration duplicate checks, user cap, rate limits, CSRF, and session protections work.
- [ ] **Every user-visible string is Indonesian**, including validation, errors, labels, plots, and accessibility text.
- [ ] Math and experiment pages remain functional and scientifically reproducible.
- [ ] Old HMAC/Argon2 tests are replaced and their removal documented transparently.
- [ ] Database migration is non-destructive by default; demo reset requires operator approval.
- [ ] Lint, unit, integration, and local HTTP smoke tests pass, with actual test counts logged.
- [ ] Live PostgreSQL/Vercel unverified status is reported faithfully unless executed.
- [ ] Updated `README.md`, `docs/architecture.md`, `docs/threat_model.md`, and `docs/agent_progress.md` describe the v2 architecture and its limitations.

---

## 13. Mandatory Agent Progress Log Format

Append a new section to `docs/agent_progress.md` (do not overwrite previous milestones):

```markdown
## Change Request CR-002 — CLEFIA-only credentials & Indonesian UI

### Phase completed
- Scope/files changed:
- Commands actually executed:
- Tests: passed / failed / skipped:
- Mathematical regression result:
- Indonesian UI review:
- Migration and compatibility notes:
- Known risks / unresolved issues:
- Next step:
```

**Agent rule:** do not assert that original HMAC-tamper rejection tests pass after removing HMAC, and do not claim the new CTR-only design provides authenticated encryption. If tests are skipped because external services are unavailable, report them as blocked or pending.

---

## 14. Ready-to-Paste Agent Prompt

> Continue the **existing** CLEFIA-128 capstone repository using `CLEFIA128_PRD_v2_0_Indonesia_CLEFIA_Only.md` as the new authoritative PRD; copy it to the repository's `PRD.md` only after preserving the previous version in version control. Read `docs/agent_progress.md` and audit existing code before editing. Implement **CR-002**, not a new project. Keep the verified pure-Python CLEFIA-128 mathematical core, official vectors, avalanche/SAC/benchmark experiments, FastAPI, PostgreSQL, Vercel configuration, sessions, and **mandatory Profile Note**. Remove Argon2id, HMAC authentication tags, and HMAC username blind indices from the active app. Encrypt synthetic usernames, passwords, and notes using CLEFIA-128 CTR with a fresh unique nonce per field. Implement **Approach A**: scan and decrypt stored usernames during login and registration duplicate checks, then decrypt only the matching stored password and compare it temporarily in server memory. Apply strict small-demo limits and preserve CSRF/rate limiting/owner isolation. Translate **all user-facing application text** into natural Bahasa Indonesia, including errors, form labels, mathematics, charts, and image alt text. Keep the explicit academic-only and CTR-without-integrity warnings. Create non-destructive migrations; do not automatically delete data. Rerun existing mathematical tests, rewrite obsolete HMAC/Argon2 tests, run lint and full regression, and append actual results and remaining blockers to `docs/agent_progress.md`. Never claim live PostgreSQL/Vercel tests passed without running them.

---

## 15. References

1. Sony Corporation, *The 128-bit Blockcipher CLEFIA — Specification v1.0* — https://www.sony.co.jp/en/Products/cryptography/clefia/download/data/clefia-spec-1.0.pdf
2. Katagi and Moriai, *RFC 6114: The 128-Bit Blockcipher CLEFIA* (2011) — https://www.rfc-editor.org/rfc/rfc6114.html
3. Shirai et al., *The 128-bit Blockcipher CLEFIA* (2007), uploaded project reference.
4. Gea, *Analisis dan Implementasi Algoritma CLEFIA 128 untuk Meningkatkan Confusion Record Data Login User* (2022), uploaded academic application reference.
5. Existing repository progress: `docs/agent_progress.md` (M0–M7); prior PRD v1.1 and CR-001 retained as historical artifacts.
