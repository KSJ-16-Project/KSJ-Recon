"""Shared helpers for HTTP-based XSS scanners."""

from __future__ import annotations

import logging

from .csrf import extract_csrf
from .payloads import WAF_INDICATORS

logger = logging.getLogger(__name__)


_AUTH_URL_PATTERNS = (
    "login", "signin", "sign-in", "logout",
    "auth/login", "auth/failure", "auth/required", "auth/unauthorized",
    "session/new", "member/login", "user/login",
    "access-denied", "forbidden", "unauthorized", "no-permission",
)

# URL 변화 없이도 세션 만료를 확신할 수 있는 명시적 키워드 (좁은 범위)
_SESSION_EXPIRY_KEYWORDS = (
    "session expired", "session has expired",
    "please log in", "please sign in",
    "세션이 만료", "로그인이 필요", "다시 로그인",
)

# URL이 바뀌었을 때만 사용하는 넓은 키워드 (단독으로 쓰면 오탐 위험)
_AUTH_REDIRECT_KEYWORDS = _SESSION_EXPIRY_KEYWORDS + (
    "access denied", "권한이 없", "접근이 거부",
    "authentication required", "인증이 필요",
    "you must be logged in", "로그인 후 이용",
)


def auth_failed(resp, *, original_url: str | None = None) -> bool:
    if resp.status_code in {401, 403}:
        return True

    # 방법 1 — URL 패턴 매칭
    if any(p in resp.url.lower() for p in _AUTH_URL_PATTERNS):
        return True

    body_snippet = resp.text[:800].lower()

    # 방법 1 보조 — body 명시적 세션 만료 키워드 (URL 무관)
    if any(k in body_snippet for k in _SESSION_EXPIRY_KEYWORDS):
        return True

    # 방법 2 — URL 이탈 AND 넓은 키워드 (둘 다 만족할 때만 트리거)
    if original_url and resp.url.rstrip("/") != original_url.rstrip("/"):
        return any(k in body_snippet for k in _AUTH_REDIRECT_KEYWORDS)

    return False


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
