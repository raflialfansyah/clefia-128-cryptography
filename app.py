"""Vercel and local ASGI entrypoint exporting the FastAPI ``app`` instance."""

import sys
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from web import create_app  # noqa: E402

app = create_app()
