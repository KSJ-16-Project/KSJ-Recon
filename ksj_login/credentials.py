"""
credentials.py — 자격증명 보관 및 세션 획득

core가 store_credentials()로 로그인 정보를 저장해두면,
core 또는 crawler engine이 get_session()으로 세션을 요청한다.
get_session()은 브라우저를 내부에서 직접 생성하므로 호출자가 브라우저를 준비할 필요 없다.
"""

from __future__ import annotations

from playwright.async_api import async_playwright

from .form_analyzer import detect_selectors_via_dom, get_detection_failure_reason
from .login import perform_login
from .models import AuthConfig, AuthResult

_stored_login_url: str = ""
_stored_config: AuthConfig | None = None


def store_credentials(login_url: str, username: str, password: str) -> None:
    """core가 crawl_target() 호출 전에 로그인 정보를 보관한다."""
    global _stored_login_url, _stored_config
    _stored_login_url = login_url
    _stored_config = AuthConfig(username=username, password=password)


def has_credentials() -> bool:
    """저장된 자격증명이 있으면 True. crawler engine이 인증 크롤 필요 여부 판단 시 호출."""
    return _stored_config is not None and bool(_stored_login_url)


async def get_session() -> AuthResult:
    """
    저장된 자격증명으로 로그인을 수행하고 AuthResult를 반환한다.
    브라우저를 내부에서 생성하므로 호출자는 브라우저 객체를 준비할 필요 없다.

    core: 로그인 성공 여부 확인 및 재시도 루프에서 호출
    crawler engine: public 크롤 완료 후 인증 세션 획득 시 호출

    Returns:
        성공: AuthResult(success=True, cookies=[...])  — cookies가 2차 크롤에 사용됨
        실패: AuthResult(success=False, reason="...", error="...")
    """
    if not has_credentials():
        return AuthResult(success=False, reason="credentials_not_configured")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled"],
        )
        try:
            selectors = await detect_selectors_via_dom(browser, _stored_login_url)
            if selectors is None:
                return AuthResult(
                    success=False,
                    attempted=False,
                    login_url=_stored_login_url,
                    reason="login_page_not_found",
                    error=f"로그인 폼을 찾을 수 없습니다 — {get_detection_failure_reason()}",
                )

            result = await perform_login(browser, _stored_login_url, selectors, _stored_config)
            result.selectors = selectors
            result.config = _stored_config
            if not result.reason:
                result.reason = "login_success" if result.success else "login_failed"
            return result
        finally:
            await browser.close()
