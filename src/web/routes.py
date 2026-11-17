"""HTTP routes for the Indonesian CLEFIA-128 academic web demonstrator (CR-002)."""

from __future__ import annotations

import csv
import json
import math
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from clefia.cipher import trace_encrypt_block
from clefia.key_schedule import derive_intermediate_l, key_schedule_128
from clefia.record_crypto import ClefiaRecordService
from web.auth import (
    PASSWORD_FIELD,
    PROFILE_NOTE_FIELD,
    USERNAME_FIELD,
    CorruptCredentialDataError,
    DemoCapacityExceededError,
    DuplicateUsernameError,
    InvalidCredentialsError,
    RateLimitExceededError,
    ValidationError,
    authenticate_user,
    change_user_password,
    check_and_increment_rate_limit,
    create_user_session,
    issue_preauth_csrf_pair,
    read_credentials_overview,
    read_profile_note_for_owner,
    register_user,
    reset_rate_limit,
    resolve_user_session,
    revoke_user_session,
    save_profile_note,
    verify_csrf_token,
    verify_preauth_csrf,
)
from web.config import Settings
from web.models import EncryptedFieldRow, UserSession
from web.schemas import AuthenticatedUser
from web.templating import TEMPLATES

_WEB_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _WEB_DIR.parent.parent
_EXPERIMENTS_DIR = _REPO_ROOT / "experiments"

SESSION_COOKIE_NAME = "clefia_session"
PREAUTH_CSRF_COOKIE_NAME = "clefia_preauth_csrf"
_ALLOWED_PLOT_FILES = frozenset(
    {
        "avalanche_histogram.png",
        "avalanche_positions.png",
        "sac_heatmap.png",
        "benchmark.png",
    }
)

# Fixed public RFC 6114 Appendix A/B sample vector (never a production key)
_RFC_SAMPLE_KEY_HEX = "ffeeddccbbaa99887766554433221100"
_RFC_SAMPLE_PLAINTEXT_HEX = "000102030405060708090a0b0c0d0e0f"
_RFC_SAMPLE_EXPECTED_CT_HEX = "de2bf2fd9b74aacdf1298555459494fd"

router = APIRouter()


def _get_db(request: Request) -> Iterator[Session]:
    session_factory = request.app.state.session_factory
    with session_factory() as session:
        yield session


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded:
        return forwarded[:64]
    if request.client and request.client.host:
        return request.client.host[:64]
    return "unknown"


def _current_auth(
    request: Request,
    db: Session,
) -> tuple[AuthenticatedUser, UserSession] | None:
    settings: Settings = request.app.state.settings
    crypto: ClefiaRecordService = request.app.state.record_crypto
    cookie_val = request.cookies.get(SESSION_COOKIE_NAME)
    return resolve_user_session(
        db,
        crypto,
        signed_cookie=cookie_val,
        session_secret_key=settings.session_secret_key,
        max_age_seconds=settings.session_ttl_seconds,
    )


def _base_context(auth: tuple[AuthenticatedUser, UserSession] | None) -> dict[str, Any]:
    if auth is None:
        return {"current_user": None, "csrf_token": ""}
    user, user_session = auth
    return {"current_user": user, "csrf_token": user_session.csrf_token}


def _set_session_cookie(response: Response, value: str, settings: Settings) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=value,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        path="/",
    )


def _clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        path="/",
    )


def _set_preauth_csrf_cookie(response: Response, value: str, settings: Settings) -> None:
    response.set_cookie(
        key=PREAUTH_CSRF_COOKIE_NAME,
        value=value,
        max_age=3600,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        path="/",
    )


def _build_rfc_math_sample() -> dict[str, Any]:
    """Compute RFC 6114 Appendix A/B public test vector details for /math."""
    key = bytes.fromhex(_RFC_SAMPLE_KEY_HEX)
    pt = bytes.fromhex(_RFC_SAMPLE_PLAINTEXT_HEX)
    inter_l = derive_intermediate_l(key)
    ks = key_schedule_128(key)
    trace = trace_encrypt_block(key, pt)

    selected_indices = (0, 1, 8, 17)
    selected_rounds = [
        {
            "round_number": trace.rounds[i].round_number,
            "input_hex": " ".join(f"{w:08x}" for w in trace.rounds[i].input_words),
            "rk_hex": f"{trace.rounds[i].rk_even:08x} / {trace.rounds[i].rk_odd:08x}",
            "f_out_hex": f"{trace.rounds[i].f0_out:08x} / {trace.rounds[i].f1_out:08x}",
        }
        for i in selected_indices
    ]

    return {
        "key_hex": _RFC_SAMPLE_KEY_HEX,
        "plaintext_hex": _RFC_SAMPLE_PLAINTEXT_HEX,
        "intermediate_l_hex": inter_l.hex(),
        "wk_hex": " ".join(f"{w:08x}" for w in ks.whitening_keys),
        "rk_first_hex": " ".join(f"{w:08x}" for w in ks.round_keys[:4]),
        "rk_last_hex": " ".join(f"{w:08x}" for w in ks.round_keys[32:36]),
        "ciphertext_hex": trace.ciphertext.hex(),
        "expected_ciphertext_hex": _RFC_SAMPLE_EXPECTED_CT_HEX,
        "matches": trace.ciphertext.hex() == _RFC_SAMPLE_EXPECTED_CT_HEX,
        "selected_rounds": selected_rounds,
    }


def _summarize_avalanche_csv(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    pcts: list[float] = []
    bits_list: list[int] = []
    seed = ""
    pair_indices: set[str] = set()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            seed = row.get("seed", seed)
            if "pair_index" in row:
                pair_indices.add(row["pair_index"])
            hd = int(row["hamming_distance"])
            bits_list.append(hd)
            pcts.append(float(row["avalanche_pct"]))
    if not pcts:
        return None
    n = len(pcts)
    mean_pct = sum(pcts) / n
    mean_bits = sum(bits_list) / n
    var = sum((x - mean_pct) ** 2 for x in pcts) / max(1, n - 1)
    return {
        "seed": seed or "N/A",
        "pairs": len(pair_indices),
        "trials": n,
        "mean_pct": f"{mean_pct:.2f}",
        "mean_bits": f"{mean_bits:.2f}",
        "std_pct": f"{math.sqrt(var):.2f}",
        "min_pct": f"{min(pcts):.2f}",
        "max_pct": f"{max(pcts):.2f}",
    }


def _summarize_sac_csv(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    devs: list[float] = []
    seed = ""
    samples = 0
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            seed = row.get("seed", seed)
            samples = int(row.get("samples", samples or 0))
            prob = float(row["flip_prob"])
            devs.append(abs(prob - 0.5))
    if not devs:
        return None
    se = 0.5 / math.sqrt(samples) if samples > 0 else 0.0
    return {
        "seed": seed or "N/A",
        "samples": samples,
        "mean_abs_dev": f"{(sum(devs) / len(devs)):.4f}",
        "max_abs_dev": f"{max(devs):.4f}",
        "binomial_se": f"{se:.4f}",
    }


def _load_experiment_summary() -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    results_dir = _EXPERIMENTS_DIR / "results"
    plots_dir = _EXPERIMENTS_DIR / "plots"

    av_pt = _summarize_avalanche_csv(results_dir / "avalanche_plaintext.csv")
    av_key = _summarize_avalanche_csv(results_dir / "avalanche_key.csv")
    sac = _summarize_sac_csv(results_dir / "sac_matrix.csv")

    benchmark = None
    bench_path = results_dir / "benchmark.json"
    if bench_path.is_file():
        raw_bench = json.loads(bench_path.read_text(encoding="utf-8"))
        ops = []
        for name, metrics in raw_bench.get("operations", {}).items():
            ops.append(
                {
                    "name": name,
                    "median_us": f"{metrics['median_ns'] / 1000.0:.2f}",
                    "mean_us": f"{metrics['mean_ns'] / 1000.0:.2f}",
                    "p95_us": f"{metrics['p95_ns'] / 1000.0:.2f}",
                    "ops_per_sec": f"{metrics['ops_per_sec']:.1f}",
                }
            )
        benchmark = {
            "seed": raw_bench.get("seed"),
            "batches": raw_bench.get("batches"),
            "iterations_per_batch": raw_bench.get("iterations_per_batch"),
            "environment": raw_bench.get("environment", {}),
            "operations": ops,
        }

    plot_meta = [
        (
            "avalanche_histogram.png",
            "Distribusi Jarak Hamming Efek Avalanche CLEFIA-128",
            "Histogram distribusi jarak Hamming keluaran pada eksperimen efek avalanche.",
        ),
        (
            "avalanche_positions.png",
            "Persentase Efek Avalanche Rata-Rata per Posisi Bit Masukan",
            "Grafik rata-rata persentase perubahan bit keluaran untuk setiap posisi bit masukan.",
        ),
        (
            "sac_heatmap.png",
            "Peta Panas Kriteria Avalanche Ketat (SAC) Empiris 128x128",
            "Peta panas probabilitas perubahan bit keluaran terhadap bit masukan 128x128.",
        ),
        (
            "benchmark.png",
            "Perbandingan Waktu Eksekusi Primitif CLEFIA-128",
            "Diagram batang waktu eksekusi median dan persentil ke-95 dalam mikrodetik.",
        ),
    ]
    plots = [
        {"filename": fname, "title": title, "alt": alt}
        for fname, title, alt in plot_meta
        if (plots_dir / fname).is_file()
    ]

    if not any((av_pt, av_key, sac, benchmark, plots)):
        return None, []
    return {
        "avalanche_plaintext": av_pt,
        "avalanche_key": av_key,
        "sac": sac,
        "benchmark": benchmark,
    }, plots


@router.get("/health")
def health(request: Request) -> JSONResponse:
    """Minimal service health endpoint without exposing secrets."""
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is not None:
        try:
            with session_factory() as db:
                db.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"status": "error", "service": "clefia128-capstone"},
            )
    return JSONResponse(
        status_code=200,
        content={"status": "ok", "service": "clefia128-capstone"},
    )


@router.get("/", response_class=HTMLResponse)
def landing(request: Request) -> HTMLResponse:
    """Halaman beranda aplikasi demonstrasi CLEFIA-128 berbahasa Indonesia."""
    with request.app.state.session_factory() as db:
        auth = _current_auth(request, db)
        ctx = _base_context(auth)
    return TEMPLATES.TemplateResponse(request, "index.html", ctx)


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request) -> HTMLResponse:
    """Tampilkan formulir pendaftaran akun simulasi ber-CSRF."""
    settings: Settings = request.app.state.settings
    raw_token, cookie_val, should_set = issue_preauth_csrf_pair(
        settings.session_secret_key,
        request.cookies.get(PREAUTH_CSRF_COOKIE_NAME),
    )
    with request.app.state.session_factory() as db:
        auth = _current_auth(request, db)
        ctx = {
            **_base_context(auth),
            "error": None,
            "username": "",
            "preauth_csrf_token": raw_token,
        }
    resp = TEMPLATES.TemplateResponse(request, "register.html", ctx)
    if should_set:
        _set_preauth_csrf_cookie(resp, cookie_val, settings)
    return resp


@router.post("/register", response_class=HTMLResponse)
def register_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    password_confirm: str = Form(""),
    csrf_token: str | None = Form(None),
) -> Response:
    """Buat akun simulasi dengan enkripsi CLEFIA-128-CTR pada nama pengguna dan kata sandi."""
    settings: Settings = request.app.state.settings
    crypto: ClefiaRecordService = request.app.state.record_crypto
    preauth_cookie = request.cookies.get(PREAUTH_CSRF_COOKIE_NAME)

    if not verify_preauth_csrf(settings.session_secret_key, preauth_cookie, csrf_token):
        raw_token, cookie_val, _ = issue_preauth_csrf_pair(settings.session_secret_key, None)
        with request.app.state.session_factory() as db:
            auth = _current_auth(request, db)
            resp = TEMPLATES.TemplateResponse(
                request,
                "register.html",
                {
                    **_base_context(auth),
                    "error": (
                        "Token keamanan formulir (CSRF) tidak valid atau kedaluwarsa. "
                        "Silakan kirim ulang formulir."
                    ),
                    "username": username,
                    "preauth_csrf_token": raw_token,
                },
                status_code=403,
            )
        _set_preauth_csrf_cookie(resp, cookie_val, settings)
        return resp

    raw_token, cookie_val, should_set = issue_preauth_csrf_pair(
        settings.session_secret_key, preauth_cookie
    )

    with request.app.state.session_factory() as db:
        auth = _current_auth(request, db)
        bucket = f"register:{_client_ip(request)}"
        try:
            check_and_increment_rate_limit(
                db,
                bucket_key=bucket,
                max_attempts=settings.rate_limit_max_attempts,
                window_seconds=settings.rate_limit_window_seconds,
            )
            if password != password_confirm:
                raise ValidationError("Konfirmasi kata sandi tidak cocok.")
            register_user(
                db,
                crypto,
                username=username,
                password=password,
                max_users=settings.demo_max_users,
            )
        except RateLimitExceededError as exc:
            resp = TEMPLATES.TemplateResponse(
                request,
                "register.html",
                {
                    **_base_context(auth),
                    "error": str(exc),
                    "username": username,
                    "preauth_csrf_token": raw_token,
                },
                status_code=429,
            )
            if should_set:
                _set_preauth_csrf_cookie(resp, cookie_val, settings)
            return resp
        except (ValidationError, DuplicateUsernameError, DemoCapacityExceededError) as exc:
            resp = TEMPLATES.TemplateResponse(
                request,
                "register.html",
                {
                    **_base_context(auth),
                    "error": str(exc),
                    "username": username,
                    "preauth_csrf_token": raw_token,
                },
                status_code=400,
            )
            if should_set:
                _set_preauth_csrf_cookie(resp, cookie_val, settings)
            return resp

    return RedirectResponse(url="/login?registered=1", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    registered: str | None = None,
    logged_out: str | None = None,
) -> HTMLResponse:
    """Tampilkan formulir masuk akun ber-CSRF."""
    settings: Settings = request.app.state.settings
    raw_token, cookie_val, should_set = issue_preauth_csrf_pair(
        settings.session_secret_key,
        request.cookies.get(PREAUTH_CSRF_COOKIE_NAME),
    )
    with request.app.state.session_factory() as db:
        auth = _current_auth(request, db)
        ctx = {
            **_base_context(auth),
            "error": None,
            "username": "",
            "registered": registered == "1",
            "logged_out": logged_out == "1",
            "preauth_csrf_token": raw_token,
        }
    resp = TEMPLATES.TemplateResponse(request, "login.html", ctx)
    if should_set:
        _set_preauth_csrf_cookie(resp, cookie_val, settings)
    return resp


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    csrf_token: str | None = Form(None),
) -> Response:
    """Autentikasi akun melalui pemindaian dekripsi nama pengguna + dekripsi kata sandi."""
    settings: Settings = request.app.state.settings
    crypto: ClefiaRecordService = request.app.state.record_crypto
    preauth_cookie = request.cookies.get(PREAUTH_CSRF_COOKIE_NAME)

    if not verify_preauth_csrf(settings.session_secret_key, preauth_cookie, csrf_token):
        raw_token, cookie_val, _ = issue_preauth_csrf_pair(settings.session_secret_key, None)
        resp = TEMPLATES.TemplateResponse(
            request,
            "login.html",
            {
                "current_user": None,
                "csrf_token": "",
                "error": (
                    "Token keamanan formulir (CSRF) tidak valid atau kedaluwarsa. "
                    "Silakan muat ulang halaman lalu coba masuk kembali."
                ),
                "username": username,
                "registered": False,
                "logged_out": False,
                "preauth_csrf_token": raw_token,
            },
            status_code=403,
        )
        _set_preauth_csrf_cookie(resp, cookie_val, settings)
        return resp

    raw_token, cookie_val, should_set = issue_preauth_csrf_pair(
        settings.session_secret_key, preauth_cookie
    )

    with request.app.state.session_factory() as db:
        bucket = f"login:{_client_ip(request)}"
        try:
            check_and_increment_rate_limit(
                db,
                bucket_key=bucket,
                max_attempts=settings.rate_limit_max_attempts,
                window_seconds=settings.rate_limit_window_seconds,
            )
            user = authenticate_user(
                db,
                crypto,
                username=username,
                password=password,
                max_users=settings.demo_max_users,
            )
        except RateLimitExceededError as exc:
            resp = TEMPLATES.TemplateResponse(
                request,
                "login.html",
                {
                    "current_user": None,
                    "csrf_token": "",
                    "error": str(exc),
                    "username": username,
                    "registered": False,
                    "logged_out": False,
                    "preauth_csrf_token": raw_token,
                },
                status_code=429,
            )
            if should_set:
                _set_preauth_csrf_cookie(resp, cookie_val, settings)
            return resp
        except InvalidCredentialsError as exc:
            resp = TEMPLATES.TemplateResponse(
                request,
                "login.html",
                {
                    "current_user": None,
                    "csrf_token": "",
                    "error": str(exc),
                    "username": username,
                    "registered": False,
                    "logged_out": False,
                    "preauth_csrf_token": raw_token,
                },
                status_code=401,
            )
            if should_set:
                _set_preauth_csrf_cookie(resp, cookie_val, settings)
            return resp

        reset_rate_limit(db, bucket_key=bucket)
        revoke_user_session(
            db,
            signed_cookie=request.cookies.get(SESSION_COOKIE_NAME),
            session_secret_key=settings.session_secret_key,
        )
        new_cookie_val, _ = create_user_session(
            db,
            user_id=user.id,
            session_secret_key=settings.session_secret_key,
            ttl_seconds=settings.session_ttl_seconds,
        )

    response = RedirectResponse(url="/dashboard", status_code=303)
    _set_session_cookie(response, new_cookie_val, settings)
    return response


@router.post("/logout")
def logout_submit(
    request: Request,
    csrf_token: str | None = Form(None),
) -> Response:
    """Hapus sesi aktif dari database dan bersihkan cookie sesi."""
    settings: Settings = request.app.state.settings
    with request.app.state.session_factory() as db:
        auth = _current_auth(request, db)
        if auth is None:
            raise HTTPException(
                status_code=401,
                detail="Autentikasi diperlukan. Silakan masuk terlebih dahulu.",
            )
        _, user_session = auth
        if not verify_csrf_token(user_session, csrf_token):
            raise HTTPException(
                status_code=403,
                detail="Token CSRF tidak valid atau tidak ditemukan.",
            )
        revoke_user_session(
            db,
            signed_cookie=request.cookies.get(SESSION_COOKIE_NAME),
            session_secret_key=settings.session_secret_key,
        )
    response = RedirectResponse(url="/login?logged_out=1", status_code=303)
    _clear_session_cookie(response, settings)
    return response


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, saved: str | None = None) -> Response:
    """Dasbor pengguna terautentikasi dengan ringkasan enkripsi & editor Catatan Profil."""
    with request.app.state.session_factory() as db:
        auth = _current_auth(request, db)
        if auth is None:
            return RedirectResponse(url="/login", status_code=303)
        user, _ = auth
        rows = db.scalars(
            select(EncryptedFieldRow).where(EncryptedFieldRow.owner_id == user.id)
        ).all()
        by_field = {row.field_name: row for row in rows}
        note_row = by_field.get(PROFILE_NOTE_FIELD)
        cred_count = int(USERNAME_FIELD in by_field) + int(PASSWORD_FIELD in by_field)
        ctx = {
            **_base_context(auth),
            "saved": saved == "1",
            "error": None,
            "has_username": USERNAME_FIELD in by_field,
            "has_password": PASSWORD_FIELD in by_field,
            "cred_count": cred_count,
            "has_record": note_row is not None,
            "record_key_id": note_row.key_id if note_row else None,
            "record_version": note_row.algorithm_version if note_row else None,
            "record_updated_at": note_row.updated_at if note_row else None,
            "current_plaintext": "",
        }
    return TEMPLATES.TemplateResponse(request, "dashboard.html", ctx)


@router.get("/credentials", response_class=HTMLResponse)
def credentials_view(request: Request, pw_changed: str | None = None) -> Response:
    """Tampilkan ciphertext + nonce terenkripsi CLEFIA milik pemilik (tanpa sandi teks biasa)."""
    crypto: ClefiaRecordService = request.app.state.record_crypto
    with request.app.state.session_factory() as db:
        auth = _current_auth(request, db)
        if auth is None:
            return RedirectResponse(url="/login", status_code=303)
        user, _ = auth
        decode_error: str | None = None
        overview = None
        status_code = 200
        try:
            overview = read_credentials_overview(db, crypto, owner_id=user.id)
        except CorruptCredentialDataError as exc:
            decode_error = str(exc)
            status_code = 400

        ctx = {
            **_base_context(auth),
            "pw_changed": pw_changed == "1",
            "error": None,
            "overview": overview,
            "decode_error": decode_error,
        }
    return TEMPLATES.TemplateResponse(request, "credentials.html", ctx, status_code=status_code)


@router.get("/change-password", response_class=HTMLResponse)
def change_password_page(request: Request) -> Response:
    """Tampilkan halaman Ubah Kata Sandi Simulasi."""
    with request.app.state.session_factory() as db:
        auth = _current_auth(request, db)
        if auth is None:
            return RedirectResponse(url="/login", status_code=303)
        ctx = {
            **_base_context(auth),
            "error": None,
        }
    return TEMPLATES.TemplateResponse(request, "change_password.html", ctx)


@router.post("/change-password")
def change_password_submit(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    new_password_confirm: str = Form(""),
    csrf_token: str | None = Form(None),
) -> Response:
    """Enkripsi ulang kata sandi simulasi dengan nonce baru yang unik (wajib CSRF)."""
    crypto: ClefiaRecordService = request.app.state.record_crypto
    with request.app.state.session_factory() as db:
        auth = _current_auth(request, db)
        if auth is None:
            raise HTTPException(
                status_code=401,
                detail="Autentikasi diperlukan. Silakan masuk terlebih dahulu.",
            )
        user, user_session = auth
        if not verify_csrf_token(user_session, csrf_token):
            raise HTTPException(
                status_code=403,
                detail="Token CSRF tidak valid atau tidak ditemukan.",
            )

        try:
            if new_password != new_password_confirm:
                raise ValidationError("Konfirmasi kata sandi baru tidak cocok.")
            change_user_password(
                db,
                crypto,
                owner_id=user.id,
                current_password=current_password,
                new_password=new_password,
                keep_session_id=user_session.id,
            )
        except (ValidationError, InvalidCredentialsError, CorruptCredentialDataError) as exc:
            return TEMPLATES.TemplateResponse(
                request,
                "change_password.html",
                {
                    **_base_context(auth),
                    "error": str(exc),
                },
                status_code=400,
            )

    return RedirectResponse(url="/credentials?pw_changed=1", status_code=303)


@router.get("/profile", response_class=HTMLResponse)
def profile_view(request: Request, saved: str | None = None) -> Response:
    """Halaman Catatan Profil milik pemilik: mendekripsi catatan dengan kunci CLEFIA-128-CTR."""
    crypto: ClefiaRecordService = request.app.state.record_crypto
    with request.app.state.session_factory() as db:
        auth = _current_auth(request, db)
        if auth is None:
            return RedirectResponse(url="/login", status_code=303)
        user, _ = auth
        decode_error: str | None = None
        note_view = None
        status_code = 200
        try:
            note_view = read_profile_note_for_owner(db, crypto, owner_id=user.id)
        except CorruptCredentialDataError as exc:
            decode_error = str(exc)
            status_code = 400

        ctx = {
            **_base_context(auth),
            "saved": saved == "1",
            "error": None,
            "profile_view": note_view,
            "decode_error": decode_error,
        }
    return TEMPLATES.TemplateResponse(request, "profile.html", ctx, status_code=status_code)


@router.post("/profile")
def profile_save(
    request: Request,
    profile_note: str = Form(""),
    csrf_token: str | None = Form(None),
) -> Response:
    """Enkripsi dan simpan catatan profil pengguna dengan nonce 96-bit baru (wajib CSRF)."""
    crypto: ClefiaRecordService = request.app.state.record_crypto
    with request.app.state.session_factory() as db:
        auth = _current_auth(request, db)
        if auth is None:
            raise HTTPException(
                status_code=401,
                detail="Autentikasi diperlukan. Silakan masuk terlebih dahulu.",
            )
        user, user_session = auth
        if not verify_csrf_token(user_session, csrf_token):
            raise HTTPException(
                status_code=403,
                detail="Token CSRF tidak valid atau tidak ditemukan.",
            )
        try:
            save_profile_note(db, crypto, owner_id=user.id, note_text=profile_note)
        except ValidationError as exc:
            return TEMPLATES.TemplateResponse(
                request,
                "profile.html",
                {
                    **_base_context(auth),
                    "saved": False,
                    "error": str(exc),
                    "profile_view": None,
                    "decode_error": None,
                },
                status_code=400,
            )
    return RedirectResponse(url="/profile?saved=1", status_code=303)


@router.get("/math", response_class=HTMLResponse)
def math_page(request: Request) -> HTMLResponse:
    """Penjelasan matematis CLEFIA-128 dan jejak vektor uji publik RFC 6114."""
    with request.app.state.session_factory() as db:
        auth = _current_auth(request, db)
        ctx = {**_base_context(auth), "sample": _build_rfc_math_sample()}
    return TEMPLATES.TemplateResponse(request, "math.html", ctx)


@router.get("/experiments", response_class=HTMLResponse)
def experiments_page(request: Request) -> HTMLResponse:
    """Tampilkan ringkasan dan grafik hasil eksperimen avalanche, SAC, dan benchmark."""
    summary, plots = _load_experiment_summary()
    with request.app.state.session_factory() as db:
        auth = _current_auth(request, db)
        ctx = {**_base_context(auth), "summary": summary, "plots": plots}
    return TEMPLATES.TemplateResponse(request, "experiments.html", ctx)


@router.get("/experiments/plots/{filename}")
def experiment_plot_asset(filename: str) -> FileResponse:
    """Sajikan berkas PNG grafik eksperimen secara aman melalui allowlist."""
    if filename not in _ALLOWED_PLOT_FILES:
        raise HTTPException(status_code=404, detail="Halaman tidak ditemukan.")
    plot_path = _EXPERIMENTS_DIR / "plots" / filename
    if not plot_path.is_file():
        raise HTTPException(status_code=404, detail="Berkas grafik belum tersedia.")
    return FileResponse(path=str(plot_path), media_type="image/png")
