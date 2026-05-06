from __future__ import annotations

import subprocess
import sys

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright


_MISSING_BROWSER_MARKERS = (
    "executable doesn't exist",
    "please run",
    "playwright install",
)


def ensure_chromium() -> None:
    """Install Playwright's Chromium browser binary if it is missing."""
    try:
        _launch_probe()
        return
    except PlaywrightError as exc:
        if not _looks_like_missing_browser(exc):
            raise

    print("Playwright Chromium is missing; installing it now...", file=sys.stderr)
    result = subprocess.run(
        [sys.executable, "-m", "playwright", "install", "chromium"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout, file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        raise RuntimeError(
            "Failed to install Playwright Chromium. "
            "Run: python -m playwright install chromium"
        )

    _launch_probe()


def _launch_probe() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        browser.close()


def _looks_like_missing_browser(exc: PlaywrightError) -> bool:
    message = str(exc).lower()
    return any(marker in message for marker in _MISSING_BROWSER_MARKERS)
