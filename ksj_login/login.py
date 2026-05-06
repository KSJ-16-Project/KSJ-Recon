"""
login.py — Playwright로 로그인 폼 자동 입력 및 세션 쿠키 획득

담당자 A의 BrowserManager가 cookies 파라미터로 dict 포맷을 받으므로,
여기서는 ctx.cookies() 결과를 그대로 AuthResult.cookies로 반환한다.
"""

from __future__ import annotations

import asyncio
import re
from typing import Optional

from playwright.async_api import (
    Browser,
    BrowserContext,
    Error as PlaywrightError,
    TimeoutError as PlaywrightTimeoutError,
)

from .models import AuthConfig, AuthResult, FormSelectors

_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

# 로그인 실패 메시지 키워드 (영문 + 한국어)
_ERROR_KEYWORDS = (
    "invalid", "incorrect", "wrong", "failed", "denied", "unauthorized",
    "잘못된", "틀린", "오류", "실패", "없습니다", "존재하지", "일치하지",
)

# URL이 여전히 로그인 페이지임을 시사하는 키워드
_LOGIN_INDICATORS = ("login", "signin", "sign-in", "auth/failure", "error")


async def perform_login(
    browser: Browser,
    login_url: str,
    selectors: FormSelectors,
    config: AuthConfig,
) -> AuthResult:
    """
    로그인 페이지를 열고 폼에 입력 후 제출하여 세션 쿠키를 획득한다.

    Returns:
        성공: AuthResult(success=True, cookies=[...])
        실패: AuthResult(success=False, error="...")  — 호출자는 비인증으로 진행
    """
    ctx: Optional[BrowserContext] = None
    try:
        ctx = await browser.new_context(
            user_agent=_UA,
            ignore_https_errors=True,
        )
        page = await ctx.new_page()

        # 1. 로그인 페이지 로딩 (load 실패 시 domcontentloaded 폴백)
        try:
            await page.goto(login_url, wait_until="load", timeout=30_000)
        except PlaywrightTimeoutError:
            try:
                await page.goto(login_url, wait_until="domcontentloaded", timeout=15_000)
            except PlaywrightError as e:
                return AuthResult(success=False, attempted=True, login_url=login_url,
                                  error=f"로그인 페이지 로딩 실패: {e}")

        # 2. 폼 입력
        try:
            await page.fill(selectors.username, config.username, timeout=5_000)
            await page.fill(selectors.password, config.password, timeout=5_000)
        except PlaywrightError as e:
            return AuthResult(success=False, attempted=True, login_url=login_url,
                              error=f"폼 입력 실패: {e}")

        # 3. dialog 핸들러 등록 (alert/confirm 자동 수락) + 제출
        page.on("dialog", lambda d: asyncio.ensure_future(d.accept()))
        before_url = page.url
        try:
            await _submit_login_form(page, selectors)
        except PlaywrightError as e:
            return AuthResult(success=False, attempted=True, login_url=login_url,
                              error=f"submit 클릭 실패: {e}")

        # 4. 네비게이션 대기 — URL 변경 감지 우선, 실패 시 networkidle 폴백
        try:
            await page.wait_for_url(lambda url: url != before_url, timeout=10_000)
        except PlaywrightTimeoutError:
            try:
                await page.wait_for_load_state("networkidle", timeout=5_000)
            except PlaywrightTimeoutError:
                try:
                    await page.wait_for_timeout(1_000)
                except PlaywrightError:
                    pass

        # 5. 성공 판별
        if not await _is_login_success(page, before_url, config.success_url_pattern):
            return AuthResult(success=False, attempted=True, login_url=login_url,
                              final_url=page.url,
                              reason="login_failed",
                              error="로그인 실패 (성공 조건 미충족)")

        # 6. 쿠키 수집 (Playwright dict 포맷 그대로 반환)
        cookies = await ctx.cookies()
        storage = await _read_storage(page)
        return AuthResult(
            success=True,
            attempted=True,
            login_url=login_url,
            final_url=page.url,
            cookies=cookies,
            local_storage=storage["local_storage"],
            session_storage=storage["session_storage"],
            reason="login_success",
        )

    except PlaywrightError as e:
        return AuthResult(success=False, attempted=True, login_url=login_url,
                          error=f"Playwright 오류: {e}")
    except Exception as e:
        return AuthResult(success=False, attempted=True, login_url=login_url, error=str(e))
    finally:
        if ctx is not None:
            try:
                await ctx.close()
            except PlaywrightError:
                pass


async def _submit_login_form(page, selectors: FormSelectors) -> None:
    """Click the submit control in the same form as the password field when possible."""
    password = page.locator(selectors.password).first

    try:
        submit_handle = await password.evaluate_handle("""
            el => {
                const form = el.closest('form');
                if (form) {
                    const btn = form.querySelector(
                        "button[type='submit'], input[type='submit'], button, [role='button']"
                    );
                    if (btn) return btn;
                }
                const parent = (form && form.parentElement) || el.closest('div, section, main') || document.body;
                const found = parent.querySelector(
                    "button[onclick], a[onclick], button[type='submit'], input[type='submit']"
                );
                if (found) return found;

                // javascript: href 버튼 fallback — password 이후 DOM 순서로 첫 번째 후보
                const allEls = Array.from(document.body.querySelectorAll('*'));
                const pwIdx = allEls.indexOf(el);
                for (const cand of allEls.slice(pwIdx + 1)) {
                    if (cand.tagName === 'A' && (cand.getAttribute('href') || '').startsWith('javascript:'))
                        return cand;
                    if (cand.tagName === 'INPUT' && cand.type === 'image')
                        return cand;
                }
                return null;
            }
        """)
        submit_el = submit_handle.as_element()
        if submit_el is not None:
            await submit_el.click(timeout=5_000)
            return
    except PlaywrightError:
        pass

    try:
        submit_btn = page.locator(selectors.submit).first
        await submit_btn.click(timeout=5_000)
        return
    except PlaywrightError:
        pass

    await password.press("Enter", timeout=5_000)


async def _read_storage(page) -> dict:
    try:
        return await page.evaluate("""
            () => ({
                local_storage: Object.fromEntries(Object.entries(window.localStorage || {})),
                session_storage: Object.fromEntries(Object.entries(window.sessionStorage || {})),
            })
        """)
    except PlaywrightError:
        return {"local_storage": {}, "session_storage": {}}


async def _is_login_success(page, before_url: str, pattern: str) -> bool:
    """
    3단계 휴리스틱으로 로그인 성공 여부 판별:
      1. success_url_pattern 정규식 매칭 (사용자 지정) → 성공
      2. URL이 변경됐고 login/signin 키워드 미포함 → 성공
         (리다이렉트 성공 → 메인 페이지 내용을 에러 키워드로 오판하지 않도록 여기서 반환)
      3. URL이 안 바뀌었거나 아직 로그인 페이지에 있는 경우에만 에러 키워드 검사 → 실패
      4. 위 어느 것도 충족 안 되면 실패
    """
    after_url = page.url.lower()

    # 1. 명시적 성공 URL 패턴
    if pattern:
        try:
            if re.search(pattern, after_url, re.IGNORECASE):
                return True
        except re.error:
            pass

    # 2. URL 변경 + 로그인 페이지 키워드 미포함 → 성공으로 판단, 이하 검사 불필요
    if after_url != before_url.lower() and not any(ind in after_url for ind in _LOGIN_INDICATORS):
        return True

    # 3. 아직 로그인 페이지에 머물러 있는 경우에만 에러 키워드 검사
    try:
        body = (await page.evaluate("document.body.innerText")).lower()
        for kw in _ERROR_KEYWORDS:
            if kw in body:
                return False
    except PlaywrightError:
        pass

    return False
