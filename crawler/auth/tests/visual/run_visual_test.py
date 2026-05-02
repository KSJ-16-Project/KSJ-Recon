"""
시각적 통합 테스트 — Layer A + Layer B를 실제 브라우저로 실행.

실행 흐름:
  1. 모의 서버 시작 (백그라운드 스레드)
  2. BrowserManager(headless=False) 로 브라우저 띄우기 ← 사용자가 직접 봄
  3. 여러 페이지 렌더링 → 폼 추출 → 페이지 목록 구성 (Layer C 자리는 mock_parser로 대체)
  4. find_login_page() — 로그인 페이지 식별
  5. analyze_login_form() — 셀렉터 추론
  6. perform_login() — 폼 자동 입력 + 제출 (브라우저 창에서 실시간 관찰)
  7. 받은 쿠키로 BrowserManager 재시작 → /dashboard 접근 (인증 유지 확인)

  실행:
    cd piscovery-main
    python -m crawler.auth.tests.visual.run_visual_test
"""

from __future__ import annotations

import asyncio
from playwright.async_api import async_playwright

from crawler.auth import (
    AuthConfig,
    find_login_page,
    analyze_login_form,
    perform_login,
)
from crawler.auth.tests.visual.mock_server import start_server, base_url
from crawler.auth.tests.visual.mock_parser import parse_forms


# 시각 확인을 위해 단계마다 잠시 대기 (초)
STEP_PAUSE = 5


async def _render(browser, url: str) -> tuple[str, int]:
    """미니 render — Layer A의 render.py 모방 (단순화 버전)."""
    ctx = await browser.new_context(ignore_https_errors=True)
    page = await ctx.new_page()
    response = await page.goto(url, wait_until="load", timeout=10_000)
    html = await page.content()
    status = response.status if response else 0
    await ctx.close()
    return html, status


async def _crawl_first_pass(browser, target_url: str) -> list[dict]:
    """1차 얕은 크롤 (모의). 홈 + 후보 링크들 방문."""
    urls = [
        f"{target_url}/",
        f"{target_url}/login",
        f"{target_url}/search",
        f"{target_url}/signup",
    ]
    pages = []
    for url in urls:
        print(f"  [1차 크롤] {url}")
        html, status = await _render(browser, url)
        if status == 200:
            pages.append(parse_forms(url, html))
    return pages


def _print_step(num: int, title: str) -> None:
    print()
    print("=" * 72)
    print(f"  STEP {num}. {title}")
    print("=" * 72)


async def main():
    # 모의 서버
    _print_step(0, "모의 서버 시작")
    server, _ = start_server()
    target = base_url()
    print(f"  서버 URL: {target}")
    print(f"  유효 자격증명: admin / 1234")

    # Playwright 직접 사용 (Layer A의 BrowserManager 대용)
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=False,           # ← 브라우저 창이 떠야 눈으로 볼 수 있음
            args=["--no-sandbox"],
        )

        try:
            # 1차 크롤
            _print_step(1, "1차 얕은 크롤 (비인증)")
            pages = await _crawl_first_pass(browser, target)
            print(f"\n  수집된 페이지 {len(pages)}개")
            for p in pages:
                print(f"    - {p['url']}  (forms={len(p['forms'])}개)")
            await asyncio.sleep(STEP_PAUSE)

            # 로그인 페이지 식별
            _print_step(2, "find_login_page() — 로그인 페이지 식별")
            login_page = find_login_page(pages)
            if login_page is None:
                print("  ❌ 로그인 페이지 미발견 — 테스트 중단")
                return
            print(f"  ✓ 로그인 페이지: {login_page['url']}")
            print(f"  ✓ 매칭된 폼 필드: {[f['name'] for f in login_page['_login_form']['fields']]}")
            await asyncio.sleep(STEP_PAUSE)

            # 폼 분석
            _print_step(3, "analyze_login_form() — 셀렉터 추론")
            sel = analyze_login_form(login_page)
            print(f"  username: {sel.username}")
            print(f"  password: {sel.password}")
            print(f"  submit:   {sel.submit[:60]}...")
            await asyncio.sleep(STEP_PAUSE)

            # 로그인 시도 (브라우저 창에서 직접 보임!)
            _print_step(4, "perform_login() — 실제 폼 자동 입력")
            print("  → 브라우저 창에서 폼 입력 과정을 직접 확인하세요")
            cfg = AuthConfig(username="admin", password="1234")
            result = await perform_login(browser, login_page["url"], sel, cfg)
            await asyncio.sleep(STEP_PAUSE)

            if result.success:
                print(f"  ✓ 로그인 성공!")
                print(f"  ✓ 쿠키 {len(result.cookies)}개 획득:")
                for c in result.cookies:
                    print(f"      {c['name']}={c['value']}  domain={c.get('domain', '?')}")
            else:
                print(f"  ❌ 로그인 실패: {result.error}")
                return

            # 인증된 상태로 보호된 페이지 접근
            _print_step(5, "쿠키 주입 후 /dashboard 접근 (인증 유지 확인)")
            ctx = await browser.new_context(ignore_https_errors=True)
            await ctx.add_cookies(result.cookies)   # ← Layer A의 BrowserManager(cookies=...)와 동일 효과
            page = await ctx.new_page()
            await page.goto(f"{target}/dashboard", wait_until="load")
            content = await page.content()
            await asyncio.sleep(STEP_PAUSE)

            if "환영합니다" in content:
                print("  ✓ /dashboard 인증 통과 — 쿠키 주입 성공")
            else:
                print(f"  ❌ /dashboard 접근 실패")
                print(f"     응답 본문 일부: {content[:200]}")
            await ctx.close()

            # 실패 케이스도 확인
            _print_step(6, "잘못된 자격증명 시나리오 (Graceful Degradation)")
            bad_cfg = AuthConfig(username="hacker", password="wrong")
            bad_result = await perform_login(browser, login_page["url"], sel, bad_cfg)
            await asyncio.sleep(STEP_PAUSE)

            if not bad_result.success:
                print(f"  ✓ 예상대로 실패: {bad_result.error}")
                print("  ✓ 호출자는 빈 cookies로 비인증 크롤 진행 가능")

            print()
            print("=" * 72)
            print("  테스트 완료. 5초 후 브라우저 종료합니다...")
            print("=" * 72)
            await asyncio.sleep(5)

        finally:
            await browser.close()
            server.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
