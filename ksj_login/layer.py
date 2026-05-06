from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

from playwright.async_api import Browser, Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError

from .detector import find_login_page
from .form_analyzer import analyze_login_form
from .login import perform_login
from .models import AuthConfig, AuthResult, FormSelectors


async def run_login(
    browser: Browser,
    pages: list[Any],
    config: AuthConfig,
) -> AuthResult:
    if not config.enabled:
        return AuthResult(success=False, reason="auth_disabled")
    if not config.username or not config.password:
        return AuthResult(success=False, reason="credentials_not_configured")

    normalised = _normalise_pages(pages)
    login_page = find_login_page(normalised)

    if login_page is not None:
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
        login_url = login_page["url"]
    else:
        # <form> 밖에 있는 input 처리: Playwright로 직접 DOM 탐지
        login_url, selectors = await _detect_form_with_playwright(browser, normalised)
        if login_url is None:
            return AuthResult(success=False, reason="login_page_not_found")

    result = await perform_login(browser, login_url, selectors, config)
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


async def _detect_form_with_playwright(
    browser: Browser,
    pages: list[dict],
) -> tuple[str, FormSelectors] | tuple[None, None]:
    """
    <form> 태그 밖에 있는 input도 처리하기 위한 Playwright 직접 탐지 폴백.
    크롤러 데이터 기반 find_login_page()가 None을 반환할 때만 호출된다.
    각 URL을 직접 방문해 DOM에서 password input을 찾고 FormSelectors를 반환한다.
    """
    from .form_analyzer import _SUBMIT_SELECTOR

    for page_data in pages:
        url = page_data.get("url", "")
        if not url:
            continue

        ctx = None
        try:
            ctx = await browser.new_context(ignore_https_errors=True)
            page = await ctx.new_page()
            try:
                await page.goto(url, wait_until="load", timeout=30_000)
            except PlaywrightTimeoutError:
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=15_000)
                except PlaywrightError:
                    continue

            result = await page.evaluate("""
                () => {
                    const pw = document.querySelector("input[type='password']");
                    if (!pw) return null;

                    // 비활성·hidden 제외한 text/email/tel input 목록
                    const candidates = Array.from(document.querySelectorAll(
                        "input[type='text'], input[type='email'], input[type='tel'], input:not([type])"
                    )).filter(el => !el.disabled && el.type !== 'hidden');

                    // DOM 순서상 password 바로 앞에 오는 input을 username으로 선택
                    const allInputs = Array.from(document.querySelectorAll('input'));
                    const pwIndex = allInputs.indexOf(pw);
                    let username = null;
                    for (let i = candidates.length - 1; i >= 0; i--) {
                        if (allInputs.indexOf(candidates[i]) < pwIndex) {
                            username = candidates[i];
                            break;
                        }
                    }
                    if (!username && candidates.length > 0) username = candidates[0];
                    if (!username) return null;

                    function toSel(el) {
                        if (el.name) return "input[name='" + el.name + "']";
                        if (el.id)   return "#" + el.id;
                        if (el.placeholder) return "input[placeholder='" + el.placeholder + "']";
                        return "input[type='" + (el.type || "text") + "']";
                    }

                    return { username: toSel(username), password: toSel(pw) };
                }
            """)

            if result:
                return url, FormSelectors(
                    username=result["username"],
                    password=result["password"],
                    submit=_SUBMIT_SELECTOR,
                )
        except PlaywrightError:
            pass
        except Exception:
            pass
        finally:
            if ctx is not None:
                try:
                    await ctx.close()
                except PlaywrightError:
                    pass

    return None, None
