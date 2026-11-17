"""Full-stack FastAPI route tests for Indonesian UI, CR-002 CTR credentials, and Profile Note."""

from __future__ import annotations

import html
import re
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import select

from web import create_app
from web.auth import PASSWORD_FIELD, PROFILE_NOTE_FIELD, USERNAME_FIELD
from web.config import Settings
from web.models import EncryptedFieldRow

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _extract_csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    assert match is not None, "Expected CSRF token hidden input in HTML"
    return match.group(1)


def _build_test_app(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name: str = "routes_v2.db",
    *,
    demo_max_users: int = 100,
):
    db_file = tmp_path / name
    db_url = f"sqlite+pysqlite:///{db_file.as_posix()}"

    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("CLEFIA_ENC_KEY_HEX", "11" * 16)
    monkeypatch.setenv("CLEFIA_KEY_ID", "routes-v2")
    monkeypatch.setenv(
        "SESSION_SECRET_KEY",
        "routes-test-session-secret-with-high-entropy-9876543210",
    )
    monkeypatch.setenv("DEMO_MAX_USERS", str(demo_max_users))
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")

    alembic_cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(_REPO_ROOT / "alembic"))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(alembic_cfg, "head")

    return create_app(Settings.from_env(load_env_file=False))


def test_t014_indonesian_localization_across_pages_and_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """T-014: Public, math, experiments, auth, and HTTP error pages are localized in Indonesian."""
    app = _build_test_app(monkeypatch, tmp_path, "locale_v2.db")
    with TestClient(app) as client:
        for path in ("/", "/register", "/login", "/math", "/experiments"):
            resp = client.get(path)
            assert resp.status_code == 200
            assert 'lang="id"' in resp.text
            assert "Demonstrasi Enkripsi CLEFIA-128" in resp.text
            assert "aplikasi ini hanya untuk demonstrasi akademis" in resp.text.lower()
            assert "csrf_token" in resp.text or path in {"/", "/math", "/experiments"}

        reg_html = client.get("/register").text
        for phrase in (
            "Nama pengguna",
            "Kata sandi",
            "Konfirmasi kata sandi",
            "Buat Akun Simulasi",
        ):
            assert phrase in reg_html

        login_html = client.get("/login").text
        for phrase in ("Masuk ke Akun", "Nama pengguna", "Kata sandi"):
            assert phrase in login_html

        math_html = client.get("/math").text
        for phrase in (
            "Struktur Jaringan Feistel",
            "Substitusi S-box",
            "Perkalian pada GF(2",
            "Penjadwalan Kunci",
            "Putaran Enkripsi",
            "de2bf2fd9b74aacdf1298555459494fd",
        ):
            assert phrase in math_html

        exp_html = client.get("/experiments").text
        for phrase in (
            "Efek Avalanche",
            "Kriteria Avalanche Ketat (SAC)",
            "Perbandingan Waktu Eksekusi",
            "Jarak Hamming",
            "mikrodetik",
        ):
            assert phrase in exp_html

        # 404 & traversal error must localize cleanly in Bahasa Indonesia
        not_found = client.get("/halaman-tidak-ditemukan")
        assert not_found.status_code == 404
        assert 'lang="id"' in not_found.text
        assert "Halaman tidak ditemukan." in not_found.text
        assert client.get("/experiments/plots/..%2F..%2Fpyproject.toml").status_code == 404


def test_t013_csrf_register_login_session_renewal_and_guards(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """T-013: Pre-auth/session CSRF, session renewal, cookies, and redirect guards work."""
    app = _build_test_app(monkeypatch, tmp_path, "csrf_flow_v2.db")
    with TestClient(app) as client:
        for protected in ("/dashboard", "/credentials", "/profile", "/change-password"):
            anon = client.get(protected, follow_redirects=False)
            assert anon.status_code == 303
            assert anon.headers["location"].endswith("/login")

        # POST /register without valid preauth CSRF must return 403 Indonesian message
        bad_reg = client.post(
            "/register",
            data={
                "username": "alice_demo",
                "password": "SimulasiPass!1",
                "password_confirm": "SimulasiPass!1",
                "csrf_token": "salah",
            },
        )
        assert bad_reg.status_code == 403
        assert "Token keamanan formulir (CSRF) tidak valid" in bad_reg.text

        reg_csrf = _extract_csrf_token(client.get("/register").text)
        mismatch = client.post(
            "/register",
            data={
                "username": "alice_demo",
                "password": "SimulasiPass!1",
                "password_confirm": "BerbedaPass!2",
                "csrf_token": reg_csrf,
            },
        )
        assert mismatch.status_code == 400
        assert "Konfirmasi kata sandi tidak cocok." in mismatch.text

        reg = client.post(
            "/register",
            data={
                "username": "  Alice_Demo  ",
                "password": "SimulasiPass!1",
                "password_confirm": "SimulasiPass!1",
                "csrf_token": reg_csrf,
            },
            follow_redirects=False,
        )
        assert reg.status_code == 303
        assert reg.headers["location"].endswith("/login?registered=1")

        # Duplicate normalized username returns 400 Indonesian message
        dup = client.post(
            "/register",
            data={
                "username": "alice_demo",
                "password": "OtherPass!123",
                "password_confirm": "OtherPass!123",
                "csrf_token": reg_csrf,
            },
        )
        assert dup.status_code == 400
        assert "Nama pengguna sudah digunakan." in dup.text

        # POST /login without valid preauth CSRF -> 403
        assert (
            client.post(
                "/login",
                data={"username": "alice_demo", "password": "SimulasiPass!1"},
            ).status_code
            == 403
        )

        login_csrf = _extract_csrf_token(client.get("/login").text)
        login1 = client.post(
            "/login",
            data={
                "username": "ALICE_DEMO",
                "password": "SimulasiPass!1",
                "csrf_token": login_csrf,
            },
            follow_redirects=False,
        )
        assert login1.status_code == 303
        assert login1.headers["location"].endswith("/dashboard")
        cookie1 = client.cookies.get("clefia_session")
        assert cookie1 is not None
        set_cookie_hdr = login1.headers.get("set-cookie", "").lower()
        assert "httponly" in set_cookie_hdr
        assert "samesite=lax" in set_cookie_hdr

        dash = client.get("/dashboard")
        assert dash.status_code == 200
        assert "Dasbor" in dash.text
        assert "alice_demo" in dash.text
        assert "SimulasiPass!1" not in dash.text
        assert "no-store" in dash.headers.get("cache-control", "").lower()

        # Re-login issues a new session token and revokes the previous one
        login2 = client.post(
            "/login",
            data={
                "username": "alice_demo",
                "password": "SimulasiPass!1",
                "csrf_token": login_csrf,
            },
            follow_redirects=False,
        )
        assert login2.status_code == 303
        cookie2 = client.cookies.get("clefia_session")
        assert cookie2 is not None and cookie2 != cookie1

        with TestClient(app) as stale_client:
            stale_client.cookies.set("clefia_session", cookie1)
            assert stale_client.get("/dashboard", follow_redirects=False).status_code == 303


def test_t007_t010_t020_credentials_and_change_password_routes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """T-007/T-010/T-020: /credentials & /change-password expose no password plaintext."""
    app = _build_test_app(monkeypatch, tmp_path, "creds_pw_v2.db")
    old_pw = "RahasiaAwal!123"
    new_pw = "RahasiaBaru!456"

    with TestClient(app) as anon:
        unauth = anon.post(
            "/change-password",
            data={
                "current_password": old_pw,
                "new_password": new_pw,
                "new_password_confirm": new_pw,
            },
        )
        assert unauth.status_code == 401
        assert "Autentikasi diperlukan" in unauth.text

    with TestClient(app) as client:
        reg_csrf = _extract_csrf_token(client.get("/register").text)
        client.post(
            "/register",
            data={
                "username": "mhs_test",
                "password": old_pw,
                "password_confirm": old_pw,
                "csrf_token": reg_csrf,
            },
        )
        login_csrf = _extract_csrf_token(client.get("/login").text)
        client.post(
            "/login",
            data={"username": "mhs_test", "password": old_pw, "csrf_token": login_csrf},
        )

        creds = client.get("/credentials")
        assert creds.status_code == 200
        assert "Data Terenkripsi" in creds.text
        assert "Ciphertext (heksadesimal)" in creds.text
        assert "Nonce (heksadesimal)" in creds.text
        assert "CLEFIA-128" in creds.text
        assert old_pw not in creds.text

        with app.state.session_factory() as db:
            rows = {
                r.field_name: r for r in db.scalars(select(EncryptedFieldRow)).all()
            }
            assert USERNAME_FIELD in rows and PASSWORD_FIELD in rows
            assert rows[USERNAME_FIELD].nonce.hex() in creds.text
            assert rows[PASSWORD_FIELD].nonce.hex() in creds.text
            assert rows[PASSWORD_FIELD].ciphertext.hex() in creds.text
            old_pw_nonce = rows[PASSWORD_FIELD].nonce

        pw_page = client.get("/change-password")
        assert pw_page.status_code == 200
        assert "Ubah Kata Sandi Simulasi" in pw_page.text
        csrf = _extract_csrf_token(pw_page.text)

        # Wrong CSRF -> 403
        assert (
            client.post(
                "/change-password",
                data={
                    "current_password": old_pw,
                    "new_password": new_pw,
                    "new_password_confirm": new_pw,
                    "csrf_token": "salah",
                },
            ).status_code
            == 403
        )

        # Password confirm mismatch -> 400 Indonesian message
        bad_confirm = client.post(
            "/change-password",
            data={
                "current_password": old_pw,
                "new_password": new_pw,
                "new_password_confirm": "Lain!7890",
                "csrf_token": csrf,
            },
        )
        assert bad_confirm.status_code == 400
        assert "Konfirmasi kata sandi baru tidak cocok." in bad_confirm.text

        ok = client.post(
            "/change-password",
            data={
                "current_password": old_pw,
                "new_password": new_pw,
                "new_password_confirm": new_pw,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert ok.status_code == 303
        assert ok.headers["location"].endswith("/credentials?pw_changed=1")
        creds_after = client.get("/credentials?pw_changed=1")
        assert "Kata sandi berhasil diperbarui." in creds_after.text
        assert new_pw not in creds_after.text

        with app.state.session_factory() as db:
            new_pw_nonce = db.scalar(
                select(EncryptedFieldRow.nonce).where(
                    EncryptedFieldRow.field_name == PASSWORD_FIELD
                )
            )
            assert new_pw_nonce != old_pw_nonce

        # Log out and verify old password fails while new password logs in cleanly
        client.post("/logout", data={"csrf_token": csrf})
        assert (
            client.post(
                "/login",
                data={"username": "mhs_test", "password": old_pw, "csrf_token": login_csrf},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/login",
                data={"username": "mhs_test", "password": new_pw, "csrf_token": login_csrf},
                follow_redirects=False,
            ).status_code
            == 303
        )


def test_t011_mandatory_profile_note_route_isolation_and_bad_utf8(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """T-011/T-012: /profile enforces CSRF, owner isolation, and safe UTF-8 errors."""
    app = _build_test_app(monkeypatch, tmp_path, "profile_v2.db")
    alice_note = "Catatan profil mahasiswa berbahasa Indonesia dengan panjang > 16 byte."

    with TestClient(app) as client_alice:
        reg_csrf = _extract_csrf_token(client_alice.get("/register").text)
        client_alice.post(
            "/register",
            data={
                "username": "cat_alice",
                "password": "AlicePass!123",
                "password_confirm": "AlicePass!123",
                "csrf_token": reg_csrf,
            },
        )
        login_csrf = _extract_csrf_token(client_alice.get("/login").text)
        client_alice.post(
            "/login",
            data={
                "username": "cat_alice",
                "password": "AlicePass!123",
                "csrf_token": login_csrf,
            },
        )

        dash_csrf = _extract_csrf_token(client_alice.get("/dashboard").text)
        assert (
            client_alice.post("/profile", data={"profile_note": alice_note}).status_code == 403
        )

        saved = client_alice.post(
            "/profile",
            data={"profile_note": alice_note, "csrf_token": dash_csrf},
            follow_redirects=False,
        )
        assert saved.status_code == 303
        assert saved.headers["location"].endswith("/profile?saved=1")

        prof = client_alice.get("/profile?saved=1")
        assert prof.status_code == 200
        assert "Catatan Profil" in prof.text
        assert "Catatan berhasil disimpan dalam bentuk terenkripsi." in prof.text
        assert alice_note in html.unescape(prof.text)

        # Second owner Bob cannot view Alice's note or metadata
        with TestClient(app) as client_bob:
            bob_reg_csrf = _extract_csrf_token(client_bob.get("/register").text)
            client_bob.post(
                "/register",
                data={
                    "username": "cat_bob",
                    "password": "BobPass!123",
                    "password_confirm": "BobPass!123",
                    "csrf_token": bob_reg_csrf,
                },
            )
            bob_login_csrf = _extract_csrf_token(client_bob.get("/login").text)
            client_bob.post(
                "/login",
                data={
                    "username": "cat_bob",
                    "password": "BobPass!123",
                    "csrf_token": bob_login_csrf,
                },
            )
            bob_prof = client_bob.get("/profile")
            assert bob_prof.status_code == 200
            assert alice_note not in bob_prof.text
            assert alice_note not in client_bob.get("/credentials").text

        # Corrupt stored profile note to invalid UTF-8 -> 400 safe Indonesian error
        with app.state.session_factory() as db:
            note_row = db.scalar(
                select(EncryptedFieldRow).where(
                    EncryptedFieldRow.field_name == PROFILE_NOTE_FIELD
                )
            )
            assert note_row is not None
            bad_ct = app.state.record_crypto.encrypt_bytes(b"\xff\xfe").ciphertext
            note_row.ciphertext = bad_ct
            db.commit()

        corrupt_resp = client_alice.get("/profile")
        assert corrupt_resp.status_code == 400
        assert "Gagal Mendekode Catatan:" in corrupt_resp.text


def test_rate_limit_429_logout_and_demo_cap_routes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Rate limit returns Indonesian 429; logout clears session; demo cap rejects extras."""
    app = _build_test_app(monkeypatch, tmp_path, "rl_cap_v2.db", demo_max_users=1)
    with TestClient(app) as client:
        reg_csrf = _extract_csrf_token(client.get("/register").text)
        client.post(
            "/register",
            data={
                "username": "rl_user",
                "password": "RateLimit!123",
                "password_confirm": "RateLimit!123",
                "csrf_token": reg_csrf,
            },
        )

        # Second registration rejected due to DEMO_MAX_USERS=1
        cap_resp = client.post(
            "/register",
            data={
                "username": "extra_user",
                "password": "RateLimit!456",
                "password_confirm": "RateLimit!456",
                "csrf_token": reg_csrf,
            },
        )
        assert cap_resp.status_code == 400
        assert "Batas kapasitas akun simulasi demo" in cap_resp.text

        login_csrf = _extract_csrf_token(client.get("/login").text)
        client.post(
            "/login",
            data={
                "username": "rl_user",
                "password": "RateLimit!123",
                "csrf_token": login_csrf,
            },
        )
        dash_csrf = _extract_csrf_token(client.get("/dashboard").text)
        assert client.post("/logout", data={"csrf_token": "bad"}).status_code == 403
        out = client.post("/logout", data={"csrf_token": dash_csrf}, follow_redirects=False)
        assert out.status_code == 303
        assert out.headers["location"].endswith("/login?logged_out=1")
        assert "Anda telah keluar dari akun." in client.get("/login?logged_out=1").text
        assert client.get("/dashboard", follow_redirects=False).status_code == 303

        for _ in range(5):
            r = client.post(
                "/login",
                data={
                    "username": "rl_user",
                    "password": "WrongPassword!1",
                    "csrf_token": login_csrf,
                },
            )
            assert r.status_code == 401
            assert "Nama pengguna atau kata sandi salah." in r.text
        r6 = client.post(
            "/login",
            data={
                "username": "rl_user",
                "password": "WrongPassword!1",
                "csrf_token": login_csrf,
            },
        )
        assert r6.status_code == 429
        assert "Terlalu banyak percobaan. Coba lagi nanti." in r6.text
