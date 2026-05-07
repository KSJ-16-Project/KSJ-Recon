from __future__ import annotations

import asyncio

from playwright.async_api import Browser

from .login import perform_login
from .models import AuthResult


async def relogin(
    browser: Browser,
    prev_result: AuthResult,
    max_retries: int = 3,
    retry_delay: float = 2.0,
) -> AuthResult:
    """세션 만료 시 이전 로그인 정보로 재로그인한다. 실패 시 max_retries번까지 재시도."""
    if not prev_result.login_url or not prev_result.selectors or not prev_result.config:
        return AuthResult(success=False, reason="relogin_info_missing")

    result = AuthResult(success=False)
    for attempt in range(max_retries):
        result = await perform_login(
            browser,
            prev_result.login_url,
            prev_result.selectors,
            prev_result.config,
        )
        if result.success:
            break
        if attempt < max_retries - 1:
            await asyncio.sleep(retry_delay)

    result.selectors = prev_result.selectors
    result.config = prev_result.config
    if not result.reason:
        result.reason = "login_success" if result.success else "login_failed"
    return result
