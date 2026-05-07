"""Shared helpers for HTTP-based XSS scanners."""

from __future__ import annotations

import logging

from .csrf import extract_csrf
from .payloads import WAF_INDICATORS

logger = logging.getLogger(__name__)


def auth_failed(resp) -> bool:
    if resp.status_code in {401, 403}:
        return True
    return "login" in resp.url.lower() or "signin" in resp.url.lower()


def detect_waf(resp) -> bool:
    if resp.status_code in {403, 406, 429}:
        return True
    return any(ind in resp.text.lower() for ind in WAF_INDICATORS)


def inject_csrf(client, url: str, data: dict, headers: dict, cookies: dict) -> None:
    """Fetch a fresh CSRF token from the form page and inject into data in-place."""
    try:
        resp = client.get(url, headers=headers, cookies=cookies)
        result = extract_csrf(resp.text)
        if result:
            field, token = result
            data[field] = token
            logger.debug("CSRF token injected: %s", field)
    except Exception:
        pass
