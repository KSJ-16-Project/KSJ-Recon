from __future__ import annotations


def to_cookie_header(cookies: list[dict]) -> str:
    """Playwright 쿠키 목록 → "name=value; name2=value2" 형태 (SQLi용)"""
    return "; ".join(c["name"] + "=" + c["value"] for c in cookies if c.get("name"))


def to_cookie_dict(cookies: list[dict]) -> dict:
    """Playwright 쿠키 목록 → {"name": "value"} 형태 (XSS용)"""
    return {c["name"]: c["value"] for c in cookies if c.get("name")}
