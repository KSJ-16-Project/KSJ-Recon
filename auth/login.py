"""
login.py — Playwright로 로그인 폼 자동 입력 및 세션 쿠키 획득

담당자 A의 BrowserManager가 cookies 파라미터로 dict 포맷을 받으므로,
여기서는 ctx.cookies() 결과를 그대로 AuthResult.cookies로 반환한다.
"""

from __future__ import annotations

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
                return AuthResult(success=False, login_url=login_url,
                                  error=f"로그인 페이지 로딩 실패: {e}")

        # 2. 폼 입력
        try:
            await page.fill(selectors.username, config.username, timeout=5_000)
            await page.fill(selectors.password, config.password, timeout=5_000)
        except PlaywrightError as e:
            return AuthResult(success=False, login_url=login_url,
                              error=f"폼 입력 실패: {e}")

        # 3. 제출
        before_url = page.url
        try:
            await page.locator(selectors.submit).first.click(timeout=5_000)
        except PlaywrightError as e:
            return AuthResult(success=False, login_url=login_url,
                              error=f"submit 클릭 실패: {e}")

        # 4. 네비게이션 대기 (실패해도 무시 — 성공 판별 단계가 처리)
        try:
            await page.wait_for_load_state("load", timeout=10_000)
        except PlaywrightTimeoutError:
            pass

        # 5. 성공 판별
        if not await _is_login_success(page, before_url, config.success_url_pattern):
            return AuthResult(success=False, login_url=login_url,
                              error="로그인 실패 (성공 조건 미충족)")

        # 6. 쿠키 수집 (Playwright dict 포맷 그대로 반환)
        cookies = await ctx.cookies()
        return AuthResult(success=True, login_url=login_url, cookies=cookies)

    except PlaywrightError as e:
        return AuthResult(success=False, login_url=login_url,
                          error=f"Playwright 오류: {e}")
    except Exception as e:
        return AuthResult(success=False, login_url=login_url, error=str(e))
    finally:
        if ctx is not None:
            try:
                await ctx.close()
            except PlaywrightError:
                pass


async def _is_login_success(page, before_url: str, pattern: str) -> bool:
    """
    3단계 휴리스틱으로 로그인 성공 여부 판별:
      1. success_url_pattern 정규식 매칭 (사용자 지정)
      2. URL이 변경됐고 login/signin 키워드 미포함
      3. 페이지 본문에 오류 키워드 탐지 → 실패
      4. 위 어느 것도 충족 안 되면 실패
    """
    after_url = page.url.lower()

    # 1. 명시적 성공 URL 패턴
    if pattern:
        try:
            if re.search(pattern, after_url, re.IGNORECASE):
                return True
        except re.error:
            pass  # 잘못된 정규식은 무시하고 다음 단계로

    # 2. URL 변경 + 로그인 페이지 키워드 미포함
    if after_url != before_url.lower() and not any(ind in after_url for ind in _LOGIN_INDICATORS):
        return True

    # 3. 본문에 오류 메시지가 있으면 실패
    try:
        body = (await page.content()).lower()
        if any(kw in body for kw in _ERROR_KEYWORDS):
            return False
    except PlaywrightError:
        pass

    return False
