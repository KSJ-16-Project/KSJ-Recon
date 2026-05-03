"""Auth helper – loads credentials from login_mock.json.

Replace get_auth() body with a real HTTP login flow when ready.
Return shape must stay: {"session_id": str | None, "token": str | None}
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_MOCK = Path(__file__).resolve().parent.parent / "login_mock.json"


def get_auth(mock_path: Path | str | None = None) -> dict:
    """Return auth dict from login_mock.json (or mock_path).

    Raises FileNotFoundError if the file does not exist.
    """
    path = Path(mock_path) if mock_path else _DEFAULT_MOCK
    if not path.exists():
        raise FileNotFoundError(
            f"login_mock.json not found: {path}\n"
            "Create the file or replace get_auth() with real login logic."
        )
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    logger.info("auth loaded from %s", path)
    return {
        "session_id": data.get("session_id"),
        "token": data.get("token"),
    }
