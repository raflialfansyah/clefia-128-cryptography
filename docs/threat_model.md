# Threat Model, Security Boundaries, and Explicit Limitations (CR-002)

> **Peringatan Akademis Wajib:** **Aplikasi ini hanya untuk demonstrasi akademis algoritma CLEFIA-128. Gunakan data simulasi, bukan nama pengguna atau kata sandi asli. Enkripsi dalam mode CTR tanpa pemeriksaan autentikasi tidak dapat menjamin bahwa data terenkripsi tidak diubah.**

---

## 1. System Assets and Trust Boundaries

1. **Pure Cipher Core (`src/clefia/`):** Deterministic CLEFIA-128 block primitive (`field.py`, `sboxes.py`, `functions.py`, `gfn.py`, `constants.py`, `key_schedule.py`, `cipher.py`) with zero dependency on HTTP or database frameworks.
2. **CTR Record Boundary (`src/clefia/record_crypto.py`):** Variable-length CLEFIA-128-CTR (`ALGORITHM_VERSION = 2`) without HMAC/MAC tags, operating on UTF-8 strings (`username`, `password`, and mandatory `profile_note`) using a server-side 128-bit encryption key from environment variables.
3. **Authentication, Scan Lookup, and Session Boundary (`src/web/auth.py`, `src/web/config.py`):** `NFKC + strip + casefold` username canonicalization, bounded Approach A decrypt-and-scan lookup, serialized registration critical section (`pg_advisory_xact_lock` on PostgreSQL; lock-serialized transaction on SQLite), `secrets.compare_digest` credential checks in temporary server memory, revocable PostgreSQL-backed sessions (`user_sessions`), signed `itsdangerous` cookies (`SESSION_SECRET_KEY`, web session infrastructure only), CSRF protection on both public (`POST /register`, `POST /login`) and authenticated (`POST /profile`, `POST /change-password`, `POST /logout`) forms, and DB-backed throttling (`auth_rate_limits`).
4. **Data Persistence Boundary (`src/web/models.py`, PostgreSQL):** Stores `users` (`id`, `created_at` only), `encrypted_fields` (`'username'`, `'password'`, and mandatory `'profile_note'` rows containing `algorithm_version`, `key_id`, `nonce`, `ciphertext`), `user_sessions`, and `auth_rate_limits`. Encryption and session keys never reside in the database.

---

## 2. Threat Analysis, Mitigations, and Intentional Non-Guarantees

| # | Risk / Scenario | Behavior & Code Evidence | Verification Test |
|---|---|---|---|
| 1 | **Exposed database snapshot** | Zero plaintext usernames, zero plaintext passwords, zero password hashes, and zero lookup hashes exist in `users` or `encrypted_fields`. Credentials and `profile_note` are encrypted with CLEFIA-128-CTR (`ClefiaRecordService`) under distinct 12-byte nonces. However, passwords are **reversibly encrypted** with the server key (`CLEFIA_ENC_KEY_HEX`) — server/key compromise recovers synthetic credentials. | `T-006`, `T-020` (`tests/test_auth.py`, `tests/test_routes.py`) |
| 2 | **Ciphertext manipulation (CTR malleability)** | **NOT mitigated by design in CR-002.** Removing HMAC leaves CTR mode malleable: modifying valid-looking ciphertext bits silently modifies decrypted bytes without cryptographic detection. Structural format (`EncryptedField`) and strict UTF-8 decoding (`RecordDecodeError`) only reject malformed headers/lengths/key IDs/invalid UTF-8 sequences, returning safe generic Indonesian messages without tracebacks. | `T-012` (`tests/test_record_crypto.py`, `tests/test_auth.py`, `tests/test_routes.py`) |
| 3 | **Unauthorized cross-user read/overwrite** | Authenticated handlers resolve identity strictly from server-verified cookie + `user_sessions` DB row (`resolve_user_session`). `read_profile_note_for_owner`, `save_profile_note`, `read_credentials_overview`, and `change_user_password` filter strictly by `owner_id == current_user.id`. Decrypted passwords are never displayed or returned to browsers. | `T-011`, `T-020` (`tests/test_auth.py`, `tests/test_routes.py`) |
| 4 | **CLEFIA-128-CTR keystream / nonce reuse** | Every encryption generates a fresh 12-byte nonce via `secrets.token_bytes(12)`. `encrypted_fields` enforces `UniqueConstraint("key_id", "nonce", name="uq_encrypted_fields_key_nonce")`, `_upsert_encrypted_field` / `register_user` retry on collision (`_MAX_NONCE_RETRIES = 5`), and `clefia_ctr_crypt` rejects counter wrap past `0xFFFFFFFF`. | `T-005` (`tests/test_record_crypto.py`, `tests/test_auth.py`) |
| 5 | **Concurrent duplicate username registration** | Without a blind index, `register_user` serializes `scan -> duplicate check -> insert` inside `_registration_critical_section` (`pg_advisory_xact_lock` on PostgreSQL; thread lock on SQLite) and canonicalizes with `NFKC + strip + casefold`. | `T-008`, `T-009` (`tests/test_auth.py`) |
| 6 | **Linear O(n) login cost / DoS via mass signup** | Decrypt-and-scan requires O(n) CLEFIA decryptions per registration duplicate check and login. Mitigated for the educational scope via `DEMO_MAX_USERS` cap (default `100`), bounded query limits, and DB-backed rate limits (`auth_rate_limits`). | `T-007`, `test_rate_limit_429_logout_and_demo_cap_routes` |
| 7 | **Cross-Site Request Forgery (CSRF)** | Both public auth forms (`POST /register`, `POST /login` via signed double-submit `clefia_preauth_csrf`) and authenticated forms (`POST /profile`, `POST /change-password`, `POST /logout` via per-session `csrf_token`) validate tokens with `secrets.compare_digest` (Indonesian HTTP `403` on failure). | `T-013` (`tests/test_routes.py`) |
| 8 | **Session hijacking or replay after logout** | Session cookies wrap random tokens (stored as SHA-256 hex digests in `user_sessions.token_hash`) via `itsdangerous.URLSafeTimedSerializer`, set `HttpOnly`, `SameSite=Lax`, `Secure=True` (`staging`/`production`), renew at login, revoke other sessions on password change, revoke on `/logout`, and apply `Cache-Control: no-store`. | `T-013` (`tests/test_auth.py`, `tests/test_routes.py`) |
| 9 | **SQL injection & leaked config** | SQLAlchemy ORM bound parameters throughout; `Settings.from_env` fails closed on missing/malformed secrets or SQLite outside `APP_ENV=test`; `.env*` gitignored; `/math` uses only the public RFC 6114 sample vector. | `tests/test_smoke.py`, `tests/test_routes.py` |
| 10 | **Padding oracle / encryption oracle endpoints** | CLEFIA-128-CTR uses no padding; `/encrypt` and `/decrypt` endpoints do not exist (localized Indonesian `404`). | `tests/test_routes.py` |

---

## 3. Explicit Prototype Limitations

- **No integrity protection:** Because HMAC was intentionally removed per CR-002, an attacker with database write access can alter CTR ciphertext silently. Never use CTR-without-MAC for real systems.
- **Reversible passwords & synthetic-only use:** Demo passwords can be decrypted with `CLEFIA_ENC_KEY_HEX`. Real passwords and real personal data are strictly prohibited.
- **O(n) credential scan:** Approach A decrypt-and-scan is intentionally educational and unsuitable beyond small synthetic datasets (`DEMO_MAX_USERS`).
- **Software timing side channels:** Table-based S-boxes in pure Python are not cache-timing hardened.
- **Experiment scope:** ~50% avalanche and empirical SAC convergence measure diffusion on the block primitive, not a formal proof against cryptanalysis.
