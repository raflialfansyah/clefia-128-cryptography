"""Operator-controlled CLI helper to reset disposable synthetic demo tables.

Usage:
    uv run python scripts/demo_db_tools.py reset-demo-db --confirm-reset-demo-db
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import inspect, text

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from web.config import Settings  # noqa: E402
from web.db import create_db_engine  # noqa: E402


def reset_demo_database(database_url: str, *, confirm: bool) -> None:
    """Explicitly clear synthetic demo rows when `--confirm-reset-demo-db` is passed."""
    if not confirm:
        raise SystemExit("Refusing reset: pass --confirm-reset-demo-db explicitly.")
    engine = create_db_engine(database_url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        with engine.begin() as conn:
            for tbl in (
                "user_sessions",
                "encrypted_fields",
                "auth_rate_limits",
                "users",
            ):
                if tbl in tables:
                    conn.execute(text(f"DELETE FROM {tbl}"))
        print("Disposable demo database rows cleared safely.")
    finally:
        engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Operator database tools for synthetic demo data.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_reset = sub.add_parser("reset-demo-db", help="Wipe disposable synthetic demo tables.")
    p_reset.add_argument("--confirm-reset-demo-db", action="store_true")

    args = parser.parse_args()
    settings = Settings.from_env(load_env_file=True)

    if args.command == "reset-demo-db":
        reset_demo_database(settings.database_url, confirm=args.confirm_reset_demo_db)


if __name__ == "__main__":
    main()
