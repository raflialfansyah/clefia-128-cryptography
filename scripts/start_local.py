"""One-command local SQLite starter for the CLEFIA-128 CR-002 web demonstrator.

Stores persistent local demo settings (including generated CLEFIA_ENC_KEY_HEX and
SESSION_SECRET_KEY) inside the system temp directory (`clefia_v2_demo.env`) rather
than the repository workspace, so secrets stay out of Git and test fail-closed guards
remain intact while registered accounts stay decryptable across restarts.

Usage:
    uv run python scripts/start_local.py
"""

from __future__ import annotations

import argparse
import contextlib
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from dotenv import dotenv_values

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _ensure_local_env(env_file: Path, db_file: Path) -> dict[str, str]:
    """Load or initialize persistent local SQLite configuration without printing secrets."""
    defaults = {
        "APP_ENV": "test",
        "DATABASE_URL": f"sqlite+pysqlite:///{db_file.as_posix()}",
        "CLEFIA_KEY_ID": "demo-v2",
        "DEMO_MAX_USERS": "100",
        "SESSION_COOKIE_SECURE": "false",
    }
    if env_file.is_file():
        loaded = {k: str(v) for k, v in dotenv_values(env_file).items() if v is not None}
    else:
        loaded = {}

    changed = False
    for key, val in defaults.items():
        if not loaded.get(key):
            loaded[key] = val
            changed = True
    if not loaded.get("CLEFIA_ENC_KEY_HEX"):
        loaded["CLEFIA_ENC_KEY_HEX"] = secrets.token_hex(16)
        changed = True
    if not loaded.get("SESSION_SECRET_KEY"):
        loaded["SESSION_SECRET_KEY"] = secrets.token_urlsafe(48)
        changed = True

    if changed:
        lines = [
            "# Auto-generated local SQLite demo config (never commit).",
            *(f"{k}={v}" for k, v in loaded.items()),
        ]
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return loaded


def main() -> None:
    temp_dir = Path(tempfile.gettempdir())
    parser = argparse.ArgumentParser(description="Start CLEFIA-128 local SQLite demonstrator.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-reload", action="store_true")
    parser.add_argument("--env-file", type=Path, default=temp_dir / "clefia_v2_demo.env")
    parser.add_argument("--db-file", type=Path, default=temp_dir / "clefia_v2_demo.db")
    args = parser.parse_args()

    env_file = args.env_file
    db_file = args.db_file

    local_cfg = _ensure_local_env(env_file, db_file)
    child_env = os.environ.copy()
    child_env.update(local_cfg)

    print(f"Local config file : {env_file}")
    print(f"SQLite database   : {db_file}")
    print(f"Starting app at   : http://{args.host}:{args.port}")

    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(_REPO_ROOT),
        env=child_env,
        check=True,
    )

    uvicorn_cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "app:app",
        "--host",
        args.host,
        "--port",
        str(args.port),
    ]
    if not args.no_reload:
        uvicorn_cmd.append("--reload")

    with contextlib.suppress(KeyboardInterrupt):
        subprocess.run(uvicorn_cmd, cwd=str(_REPO_ROOT), env=child_env, check=False)


if __name__ == "__main__":
    main()
