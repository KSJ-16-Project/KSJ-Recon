"""
Layer B — 로그인 인증 레이어

오케스트레이터에서의 사용 흐름:
    from crawler.auth import find_login_page, analyze_login_form, perform_login, AuthConfig

    login_page = find_login_page(first_crawl_pages)
    if login_page:
        selectors = analyze_login_form(login_page)
        result = await perform_login(browser, login_page["url"], selectors, auth_config)
        if result.success:
            cookies = result.cookies   # → BrowserManager(cookies=cookies) 로 2차 크롤
"""

from .models import AuthConfig, AuthResult, FormSelectors
from .detector import find_login_page
from .form_analyzer import analyze_login_form
from .login import perform_login
from .layer import run_auth_layer

__all__ = [
    "AuthConfig",
    "AuthResult",
    "FormSelectors",
    "find_login_page",
    "analyze_login_form",
    "perform_login",
    "run_auth_layer",
]
