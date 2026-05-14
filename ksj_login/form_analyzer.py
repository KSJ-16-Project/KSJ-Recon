"""Infer Playwright selectors for a detected login form."""

from __future__ import annotations

import sys

from playwright.async_api import Browser, Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError

from .models import FormSelectors


def _dbg(*args) -> None:
    print(*args, file=sys.stderr, flush=True)


# detect_selectors_via_dom 실패 시 이유를 저장 — credentials.py가 AuthResult.error에 포함
_detection_failure_reason: str = ""


def get_detection_failure_reason() -> str:
    return _detection_failure_reason


_SUBMIT_SELECTOR = (
    "button[type=submit], input[type=submit], "
    "button:has-text('로그인'), a:has-text('로그인'), "
    "[role=button]:has-text('로그인'), "
    "button:has-text('Login'), a:has-text('Login'), "
    "button:has-text('Sign in'), a:has-text('Sign in'), "
    "button:has-text('Log in'), a:has-text('Log in'), "
    "[role=button]:has-text('Login'), [role=button]:has-text('Sign in')"
)

_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

_DOM_SELECTOR_JS = """
    () => {
        const pw = document.querySelector("input[type='password']");
        if (!pw) return null;

        const candidates = Array.from(document.querySelectorAll(
            "input[type='text'], input[type='email'], input[type='tel'], input:not([type])"
        )).filter(el => !el.disabled && el.type !== 'hidden');

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
"""


_DEBUG_LOG = "/tmp/ksj_dom_debug.txt"


def _log(msg: str) -> None:
    _dbg(msg)
    with open(_DEBUG_LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


async def detect_selectors_via_dom(browser: Browser, url: str) -> FormSelectors | None:
    """Playwright로 URL을 직접 방문해 password input 기반으로 FormSelectors를 추론한다.
    <form> 태그 밖 input도 탐지 가능."""
    global _detection_failure_reason
    ctx = None
    try:
        ctx = await browser.new_context(
            ignore_https_errors=True,
            user_agent=_UA,
            extra_http_headers={"Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8"},
        )
        page = await ctx.new_page()
        await page.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"
        )

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
        except PlaywrightError as e:
            _detection_failure_reason = f"페이지 로딩 실패: {e}"
            return None

        try:
            await page.wait_for_selector("input[type='password']", timeout=15_000)
        except PlaywrightTimeoutError:
            title = await page.title()
            body_snippet = await page.evaluate("document.body?.innerText?.slice(0, 200) ?? ''")
            _detection_failure_reason = (
                f"password input 미발견 — title={title!r}, url={page.url!r}, body={body_snippet!r}"
            )
            return None

        result = await page.evaluate(_DOM_SELECTOR_JS)
        if result:
            return FormSelectors(
                username=result["username"],
                password=result["password"],
                submit=_SUBMIT_SELECTOR,
            )
        _detection_failure_reason = "JS 셀렉터 추론 실패 (password input 있으나 username 없음)"
        return None
    except (PlaywrightError, Exception) as e:
        _detection_failure_reason = f"{type(e).__name__}: {e}"
        return None
    finally:
        if ctx is not None:
            try:
                await ctx.close()
            except PlaywrightError:
                pass