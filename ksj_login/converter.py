from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def to_cookie_header(cookies: list[dict]) -> str:
    """Playwright 쿠키 목록 → "name=value; name2=value2" 형태 (SQLi용)"""
    return "; ".join(c["name"] + "=" + c["value"] for c in cookies if c.get("name"))


def to_cookie_dict(cookies: list[dict]) -> dict:
    """Playwright 쿠키 목록 → {"name": "value"} 형태 (XSS용)"""
    seen: dict[str, str] = {}  # name → domain
    result: dict[str, str] = {}
    for c in cookies:
        if not c.get("name"):
            continue
        name = c["name"]
        domain = c.get("domain", "?")
        if name in seen:
            logger.warning(
                "duplicate cookie '%s' (%s vs %s) — last-wins",
                name, seen[name], domain,
            )
        seen[name] = domain
        result[name] = c["value"]
    return result
