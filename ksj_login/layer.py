from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

from playwright.async_api import Browser

from .detector import find_login_page
from .form_analyzer import analyze_login_form
from .login import perform_login
from .models import AuthConfig, AuthResult


async def run_login(
    browser: Browser,
    pages: list[Any],
    config: AuthConfig,
) -> AuthResult:
    if not config.enabled:
        return AuthResult(success=False, reason="auth_disabled")
    if not config.username or not config.password:
        return AuthResult(success=False, reason="credentials_not_configured")

    login_page = find_login_page(_normalise_pages(pages))
    if login_page is None:
        return AuthResult(success=False, reason="login_page_not_found")

    try:
        selectors = analyze_login_form(login_page)
    except Exception as exc:
        return AuthResult(
            success=False,
            attempted=False,
            login_url=login_page.get("url", ""),
            reason="selector_inference_failed",
            error=str(exc),
        )

    result = await perform_login(browser, login_page["url"], selectors, config)
    result.selectors = selectors
    result.config = config
    if not result.reason:
        result.reason = "login_success" if result.success else "login_failed"
    return result


def _normalise_pages(pages: list[Any]) -> list[dict]:
    out: list[dict] = []
    for page in pages:
        data = _to_dict(page)
        url = data.get("url", "")
        forms = data.get("forms")
        if forms is None:
            # crawler.parser 없이도 동작하도록 빈 리스트로 대체
            # 크롤러에서 넘어오는 페이지는 항상 forms가 포함되어 있음
            forms = []
        out.append({
            **data,
            "url": url,
            "forms": [_normalise_form(form) for form in forms],
        })
    return out


def _normalise_form(form: Any) -> dict:
    data = _to_dict(form)
    fields = []
    for field in data.get("fields", []) or []:
        f = _to_dict(field)
        if "type" not in f:
            f["type"] = f.pop("field_type", "")
        fields.append(f)
    data["fields"] = fields
    return data


def _to_dict(value: Any) -> dict:
    if isinstance(value, dict):
        return dict(value)
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "__dict__"):
        return dict(vars(value))
    return {}
