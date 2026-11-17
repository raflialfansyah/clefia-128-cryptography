"""FastAPI web demonstrator package for CLEFIA-128 (CR-002 Indonesian UI, CTR-only)."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from clefia.record_crypto import ClefiaRecordService
from web.config import Settings
from web.db import create_db_engine, create_session_factory
from web.routes import router
from web.templating import TEMPLATES

logger = logging.getLogger(__name__)
_STATIC_DIR = Path(__file__).resolve().parent / "static"

_INDONESIAN_HTTP_MESSAGES: dict[int, tuple[str, str]] = {
    400: ("Permintaan Tidak Valid", "Permintaan tidak valid. Periksa kembali isian Anda."),
    401: (
        "Autentikasi Diperlukan",
        "Autentikasi diperlukan. Silakan masuk terlebih dahulu.",
    ),
    403: ("Akses Ditolak", "Anda tidak memiliki izin untuk mengakses halaman ini."),
    404: ("Halaman Tidak Ditemukan", "Halaman tidak ditemukan."),
    405: ("Metode Tidak Diizinkan", "Metode permintaan tidak diizinkan untuk halaman ini."),
    422: ("Validasi Gagal", "Data formulir tidak valid. Periksa kembali isian Anda."),
    429: ("Terlalu Banyak Percobaan", "Terlalu banyak percobaan. Coba lagi nanti."),
    500: ("Kesalahan Server", "Terjadi kesalahan. Silakan coba lagi."),
}

_ENGLISH_DEFAULTS = frozenset(
    {
        "not found",
        "method not allowed",
        "unauthorized",
        "forbidden",
        "bad request",
        "unprocessable entity",
        "too many requests",
        "internal server error",
    }
)


def _localize_http_error(status_code: int, detail: object) -> tuple[str, str]:
    title, fallback = _INDONESIAN_HTTP_MESSAGES.get(
        status_code,
        ("Terjadi Kesalahan", "Terjadi kesalahan. Silakan coba lagi."),
    )
    if isinstance(detail, str):
        cleaned = detail.strip()
        if cleaned and cleaned.lower() not in _ENGLISH_DEFAULTS:
            return title, cleaned
    return title, fallback


def _prefers_json(request: Request) -> bool:
    if request.url.path == "/health":
        return True
    accept = request.headers.get("accept", "").lower()
    return "application/json" in accept and "text/html" not in accept


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application instance."""

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI) -> AsyncIterator[None]:
        active_settings = settings or Settings.from_env()
        engine = create_db_engine(
            active_settings.database_url,
            serverless=active_settings.serverless_db_pool,
        )
        app_instance.state.settings = active_settings
        app_instance.state.db_engine = engine
        app_instance.state.session_factory = create_session_factory(engine)
        app_instance.state.record_crypto = ClefiaRecordService(active_settings.crypto_config)
        try:
            yield
        finally:
            engine.dispose()

    application = FastAPI(
        title="Demonstrasi Enkripsi CLEFIA-128",
        version="0.2.0",
        description=(
            "Prototipe akademis CLEFIA-128-CTR berbahasa Indonesia untuk "
            "kredensial simulasi dan catatan profil (tanpa MAC)."
        ),
        lifespan=lifespan,
    )

    @application.middleware("http")
    async def add_security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        if request.url.path in {
            "/dashboard",
            "/profile",
            "/credentials",
            "/change-password",
            "/register",
            "/login",
        }:
            response.headers["Cache-Control"] = "no-store"
        return response

    @application.exception_handler(StarletteHTTPException)
    async def handle_http_exception(
        request: Request,
        exc: StarletteHTTPException,
    ) -> Response:
        title, message = _localize_http_error(exc.status_code, exc.detail)
        if _prefers_json(request):
            return JSONResponse(status_code=exc.status_code, content={"detail": message})
        return TEMPLATES.TemplateResponse(
            request,
            "error.html",
            {
                "current_user": None,
                "csrf_token": "",
                "status_code": exc.status_code,
                "error_title": title,
                "error_message": message,
            },
            status_code=exc.status_code,
        )

    @application.exception_handler(RequestValidationError)
    async def handle_validation_exception(
        request: Request,
        exc: RequestValidationError,
    ) -> Response:
        _ = exc
        title, message = _INDONESIAN_HTTP_MESSAGES[422]
        if _prefers_json(request):
            return JSONResponse(status_code=422, content={"detail": message})
        return TEMPLATES.TemplateResponse(
            request,
            "error.html",
            {
                "current_user": None,
                "csrf_token": "",
                "status_code": 422,
                "error_title": title,
                "error_message": message,
            },
            status_code=422,
        )

    @application.exception_handler(Exception)
    async def handle_unexpected_exception(
        request: Request,
        exc: Exception,
    ) -> Response:
        logger.exception("Unhandled error type=%s path=%s", type(exc).__name__, request.url.path)
        title, message = _INDONESIAN_HTTP_MESSAGES[500]
        if _prefers_json(request):
            return JSONResponse(status_code=500, content={"detail": message})
        return TEMPLATES.TemplateResponse(
            request,
            "error.html",
            {
                "current_user": None,
                "csrf_token": "",
                "status_code": 500,
                "error_title": title,
                "error_message": message,
            },
            status_code=500,
        )

    application.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
    application.include_router(router)
    return application
