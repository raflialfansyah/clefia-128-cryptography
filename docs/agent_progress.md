# Agent Execution & Verification Progress Log

---

## Current Clean Baseline — CLEFIA-128-CTR Only & Bahasa Indonesia UI (CR-002)

- **Active Specification:** `PRD.md` (`CLEFIA128_PRD_v2_0_Indonesia_CLEFIA_Only.md`).
- **Summary of Architecture:**
  - Pure-Python CLEFIA-128 mathematical core (`src/clefia/field.py`, `sboxes.py`, `functions.py`, `gfn.py`, `constants.py`, `key_schedule.py`, `cipher.py`) verified against official Sony/RFC 6114 vectors and Appendix B intermediates.
  - Simplified CLEFIA-128-CTR record wrapper (`src/clefia/record_crypto.py`: `ClefiaRecordService`, `EncryptedField`, `ClefiaKeyConfig`) with 12-byte random CSPRNG nonces and 32-bit big-endian counters starting at `1` (without HMAC authentication tags or password hashing).
  - Bounded Approach A (`decrypt-and-scan`) duplicate checks, registration, and login (`src/web/auth.py`), preserving mandatory Profile Note CRUD (`/profile`), `/credentials` ciphertext/nonce viewer (zero plaintext password exposure), `/change-password`, pre-auth & session CSRF, DB sessions, and DB throttling.
  - Complete Bahasa Indonesia (`lang="id"`) UI across all templates (including the persistent Section 11 CTR-without-MAC disclaimer banner in `base.html`, responsive `.table-scroll` tables, the step-by-step `Urutan Demonstrasi Akademis` guide on `/`, and full 18-round RFC 6114 trace + initial/final whitening states on `/math`), localized HTTP/validation error handlers (`400`/`401`/`403`/`404`/`422`/`429`/`500`), and `/experiments` with regenerated Bahasa Indonesia PNG plots.
  - Clean single-revision Alembic schema (`alembic/versions/0001_initial_schema.py` creating `users`, `encrypted_fields`, `user_sessions`, `auth_rate_limits`), opt-in reset helper (`scripts/demo_db_tools.py`), live PostgreSQL verifier (`scripts/verify_postgres.py`), and one-command local starter (`start_local.ps1` / `scripts/start_local.py`).
- **Legacy Cleanup Performed (User-Approved):**
  - Removed all earlier `v1` (Argon2 + `profile_encrypted_fields`) and `CR-001` (`0002_clefia_credentials`, `username_lookup`, `user_encrypted_fields`, `auth_tag`, `convert-cr001-notes`, and `0003` compatibility shim) migrations, scripts, tests, and archived `plan/` drafts so the repository starts from a single clean schema revision (`0001_initial_schema`).

### Verification Results (Post-Cleanup)
- **Commands executed:**
  - `uv lock --check`
  - `uv run ruff check .`
  - `uv run alembic upgrade head --sql`
  - `uv run pytest -v`
  - One-command launcher smoke test (`start_local.ps1 --no-reload --port <tmp_port> --env-file <tmp> --db-file <tmp>`)
- **Tests (passed / failed / skipped):**
  - `uv run pytest -v`: **52 passed, 0 failed, 0 skipped** (all unit, RFC 6114 vector/intermediate, 1,000 random roundtrip, CTR & negative malleability, concurrency, Approach A scan login, Profile Note, Indonesian UI, Ruff/smoke hygiene, and single-revision Alembic upgrade/downgrade/upgrade checks passed locally).
  - `uv run ruff check .`: **All checks passed**.
  - `uv lock --check`: **Resolved 50 packages**.
  - `uv run alembic upgrade head --sql`: Emitted clean PostgreSQL DDL for `0001_initial_schema`.
- **Mathematical regression baseline (`seed = 20261115`, `samples = 64`):**
  - Official test vector: `de2bf2fd9b74aacdf1298555459494fd` (exact match).
  - Avalanche mean: plaintext flip `49.9513%` (`63.9376/128` bits), key flip `49.9154%` (`63.8917/128` bits).
  - Empirical SAC: mean `|p_hat - 0.5| = 0.049363`, max `0.25`, binomial SE `0.0625`.
  - Pure-Python primitive benchmark medians: `key_schedule_128` `592.56 us`, `encrypt_block_with_schedule` `926.30 us`, `decrypt_block_with_schedule` `954.37 us`.
- **Known risks & pending remote checks:**
  - CTR mode without a MAC is intentionally malleable and passwords are encrypted reversibly under `CLEFIA_ENC_KEY_HEX`; real credentials must never be entered.
  - **Pending external verification:** Live PostgreSQL (`T-017` via `scripts/verify_postgres.py`) and live Vercel deployment (`T-018`) remain pending remote environment provisioning.
