# System Architecture and CLEFIA-128-CTR Record Format (CR-002)

## 1. Layered Architecture

```text
Browser (Bahasa Indonesia HTML / CSS / Jinja2 templates, lang="id")
        |
        v
FastAPI routes + signed HttpOnly session cookie + CSRF validation
        |
        +-----> Approach A: Bounded decrypt-and-scan lookup (`encrypted_fields.field_name = 'username'`)
        |
        +-----> ClefiaRecordService (CLEFIA-128-CTR only, no MAC / HMAC)
        |                 |
        |                 v
        |           Pure-Python CLEFIA-128 block primitive (src/clefia/)
        |
        v
PostgreSQL via SQLAlchemy 2.x + Alembic
  - users (id, created_at)
  - encrypted_fields (id, owner_id, field_name ['username' | 'password' | 'profile_note'],
      algorithm_version, key_id, nonce, ciphertext, updated_at)

Offline Research CLI (experiments/)
        |
        v
Pure-Python CLEFIA-128 primitive --> CSV / JSON / Bahasa Indonesia PNG plots
```

### Separation of Concerns

1. **`src/clefia/` (Cryptographic Core & CTR Record Wrapper):**
   - Completely independent of FastAPI, Starlette, SQLAlchemy, and environment-file loading.
   - Contains the raw 128-bit CLEFIA block cipher (`field.py`, `sboxes.py`, `functions.py`, `gfn.py`, `constants.py`, `key_schedule.py`, `cipher.py`) and the simplified CTR record wrapper (`record_crypto.py`).
2. **`src/web/` (Web Application & Persistence):**
   - Manages configuration validation (`config.py`), SQLAlchemy ORM (`db.py`, `models.py`), `NFKC + strip + casefold` username canonicalization + Approach A decrypt-and-scan registration/login + CSRF/session helpers (`auth.py`), localized Indonesian exception handlers (`__init__.py`), and HTTP handlers (`routes.py`).
   - Synthetic credentials (`username`, `password`) and mandatory `profile_note` records are encrypted exclusively via `ClefiaRecordService` (`encrypted_fields`) with zero password hashing, zero HMAC tags, and zero blind indexes.

---

## 2. CLEFIA-128-CTR Record Format (`algorithm_version = 2`, No MAC)

CLEFIA-128 alone is a 128-bit block permutation. Variable-length UTF-8 records use **CLEFIA-128 in Counter (CTR) mode** without a MAC or HMAC authentication tag under a single server-configured 128-bit key:

- `CLEFIA_ENC_KEY_HEX`: 16 bytes (32 hex chars) for CLEFIA-128 key expansion.
- `CLEFIA_KEY_ID`: non-secret ASCII/UTF-8 key version identifier (e.g., `demo-v2`), max 128 bytes.
- `DEMO_MAX_USERS`: upper bound for the educational decrypt-and-scan registry (default `100`).

> **Important Cryptographic Limitation:** CTR encryption without a MAC is malleable and does not authenticate stored ciphertext. Flipping bits in `ciphertext` flips corresponding plaintext bits deterministically upon decryption and is only caught if structural metadata or strict UTF-8 decoding fails.

### 2.1 Counter Block Format (16 bytes)

| Offset | Length | Field | Description |
|---|---|---|---|
| `0` | 12 bytes | `nonce` | Fresh CSPRNG value via `secrets.token_bytes(12)` |
| `12` | 4 bytes | `counter` | Unsigned big-endian block counter starting at `1` (`0x00000001`) |

- For block index $b \in \{0, 1, \dots, m-1\}$, the counter is $c = 1 + b$.
- Encryption and decryption reject if $c > 2^{32}-1$ (`0xFFFFFFFF`), preventing counter wrap and two-time pad reuse.
- Keystream block $K_b = \mathrm{CLEFIA\text{-}128}_{K_{\mathrm{enc}}}(\mathrm{nonce} \mathbin{\|} c)$ is XORed with plaintext/ciphertext chunk $b$ (truncated to chunk length on the final partial block). Empty plaintext yields `b""` (permitted for `profile_note` only).
- Global nonce uniqueness per `key_id` is enforced in PostgreSQL/SQLite via `UNIQUE(key_id, nonce)` on `encrypted_fields` with retry-on-collision in the application layer.

### 2.2 Canonical Binary Serialization (`EncryptedField.to_bytes` / `from_bytes`)

When serialized as a single binary envelope (for testing or export):

| Offset | Length | Field |
|---|---|---|
| `0` | 4 bytes | Magic header `b"CLF2"` |
| `4` | 2 bytes | `version` (`uint16_be`, `2`) |
| `6` | 2 bytes | `key_id_len` (`uint16_be`, `1..128`) |
| `8` | `key_id_len` | `key_id` (UTF-8) |
| `8 + key_id_len` | 12 bytes | `nonce` |
| `20 + key_id_len` | 4 bytes | `ct_len` (`uint32_be`) |
| `24 + key_id_len` | `ct_len` | `ciphertext` |

---

## 3. Relational Schema (`0001_initial_schema`)

Alembic revision `0001_initial_schema` creates the four active CR-002 tables cleanly:
- `users`: `(id, created_at)` only (no plaintext usernames, lookup hashes, or password hashes).
- `encrypted_fields`: `(id, owner_id, field_name, algorithm_version, key_id, nonce, ciphertext, updated_at)` with `UNIQUE(owner_id, field_name)` and `UNIQUE(key_id, nonce)`.
- `user_sessions` and `auth_rate_limits`: session revocation/CSRF tokens and login/registration rate-limit buckets.
