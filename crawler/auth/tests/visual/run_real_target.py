"""
실제 도메인에 대한 시각 통합 테스트.

⚠️  본인이 소유하거나 명시적으로 테스트 권한을 받은 사이트에만 사용할 것.

실행:
  python -m crawler.auth.tests.visual.run_real_target <target_url> <username> <password> [--manual]

예시:
  # 자동 모드 (1차 크롤로 로그인 페이지 자동 탐지)
  python -m crawler.auth.tests.visual.run_real_target https://hotspotfan.online myuser mypass

  # 수동 모드 (브라우저에서 직접 로그인 페이지로 이동 후 Enter)
  python -m crawler.auth.tests.visual.run_real_target https://hotspotfan.online myuser mypass --manual

흐름:
  1. target_url 홈페이지 + 발견된 내부 링크 1차 크롤
  2. 로그인 페이지 자동 식별
  3. 폼 셀렉터 추론
  4. 로그인 시도 (브라우저 창에서 직접 관찰)
  5. 쿠키 획득 후 홈페이지 재방문해 인증 상태 유지 확인
"""

from __future__ import annotations

import asyncio
import sys
from urllib.parse import urljoin, urlparse

from playwright.async_api import (
    async_playwright,
    Error as PlaywrightError,
    TimeoutError as PlaywrightTimeoutError,
)

from crawler.auth import (
    AuthConfig,
    find_login_page,
    analyze_login_form,
    perform_login,
)
from crawler.auth.tests.visual.mock_parser import parse_forms


STEP_PAUSE = 3
MAX_FIRST_PASS_LINKS = 20      # 1차 크롤에서 방문할 최대 링크 수


async def _render(browser, url: str) -> tuple[str, int, list[str]]:
    """
    URL을 렌더링해 (HTML, status, 같은 도메인 내부 링크 목록)을 반환.
    SPA 대응: JS 렌더링 완료를 networkidle + 폼 셀렉터 대기로 기다림.
    """
    ctx = await browser.new_context(ignore_https_errors=True)
    page = await ctx.new_page()
    html = ""
    status = 0
    links: list[str] = []
    try:
        # 1차 시도: networkidle (SPA JS 번들 실행 대기)
        try:
            response = await page.goto(url, wait_until="networkidle", timeout=20_000)
        except PlaywrightTimeoutError:
            # 2차 폴백: domcontentloaded
            try:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=15_000)
            except PlaywrightTimeoutError:
                response = None

        if response:
            status = response.status

        # SPA가 폼을 동적 렌더링할 시간 추가 대기
        try:
            await page.wait_for_selector(
                "input[type=password], input[type=email], form",
                timeout=5_000,
                state="attached",
            )
        except PlaywrightTimeoutError:
            pass
        # 안전 마진
        await page.wait_for_timeout(1500)

        html = await page.content()

        # 진단: 발견된 input/form 개수
        try:
            counts = await page.evaluate("""() => ({
                forms: document.querySelectorAll('form').length,
                inputs: document.querySelectorAll('input').length,
                pwds: document.querySelectorAll('input[type=password]').length,
            })""")
            print(f"      └─ DOM: forms={counts['forms']}, inputs={counts['inputs']}, pwd={counts['pwds']}")
        except PlaywrightError:
            pass
        # 같은 도메인 내부 링크만 추출
        try:
            hrefs = await page.evaluate(
                "() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href)"
            )
        except PlaywrightError:
            hrefs = []
        base_origin = urlparse(url).netloc
        seen = set()
        for h in hrefs:
            if not h.startswith("http"):
                continue
            if urlparse(h).netloc != base_origin:
                continue
            if h in seen:
                continue
            seen.add(h)
            links.append(h)
    except PlaywrightError as e:
        print(f"  [렌더 실패] {url}: {e}")
    finally:
        await ctx.close()
    return html, status, links


async def _crawl_first_pass(browser, target_url: str) -> list[dict]:
    """
    홈페이지 + 발견된 내부 링크들을 1차 얕은 크롤.
    """
    pages: list[dict] = []
    visited: set[str] = set()
    queue: list[str] = [target_url]

    # /login, /signin 같은 후보 경로를 우선 큐에 추가 (휴리스틱)
    common_paths = ["/login", "/signin", "/auth", "/account/login", "/user/login", "/admin"]
    for p in common_paths:
        queue.append(urljoin(target_url, p))

    count = 0
    while queue and count < MAX_FIRST_PASS_LINKS:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        print(f"  [{count+1}/{MAX_FIRST_PASS_LINKS}] {url}")
        html, status, links = await _render(browser, url)
        if status and status < 400 and html:
            pages.append(parse_forms(url, html))
            count += 1
            # 첫 페이지에서 발견된 링크들도 큐에 추가
            for link in links:
                if link not in visited and link not in queue:
                    queue.append(link)

    return pages


def _print_step(num: int, title: str) -> None:
    print()
    print("=" * 72)
    print(f"  STEP {num}. {title}")
    print("=" * 72)


async def _manual_capture(browser, target_url: str) -> list[dict]:
    """
    수동 모드: 브라우저를 열고 사용자가 직접 로그인 페이지로 이동한 뒤
    Enter를 눌러 현재 페이지를 캡처한다. SPA 디버깅에 유용.
    """
    ctx = await browser.new_context(ignore_https_errors=True)
    page = await ctx.new_page()
    await page.goto(target_url, wait_until="domcontentloaded", timeout=30_000)

    print()
    print("  >>> 브라우저 창에서 로그인 페이지로 직접 이동하세요.")
    print("  >>> 폼이 보이면 이 터미널에서 Enter를 누르세요. <<<")
    await asyncio.get_event_loop().run_in_executor(None, input)

    captured_url = page.url
    html = await page.content()
    print(f"  캡처된 URL: {captured_url}")

    # 진단
    try:
        counts = await page.evaluate("""() => ({
            forms: document.querySelectorAll('form').length,
            inputs: document.querySelectorAll('input').length,
            pwds: document.querySelectorAll('input[type=password]').length,
        })""")
        print(f"  DOM: forms={counts['forms']}, inputs={counts['inputs']}, pwd={counts['pwds']}")
    except PlaywrightError:
        pass

    await ctx.close()
    return [parse_forms(captured_url, html)]


async def main(target_url: str, username: str, password: str, manual: bool = False):
    _print_step(0, "실제 도메인 테스트 시작")
    print(f"  대상: {target_url}")
    print(f"  사용자: {username}")
    print(f"  모드: {'수동 (Manual)' if manual else '자동 (Auto)'}")
    print(f"  ⚠️  본인이 테스트 권한을 가진 사이트인지 확인하세요")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=False,
            args=["--no-sandbox"],
        )

        try:
            # 페이지 수집
            if manual:
                _print_step(1, "수동 캡처 모드")
                pages = await _manual_capture(browser, target_url)
            else:
                _print_step(1, f"1차 얕은 크롤 (최대 {MAX_FIRST_PASS_LINKS}개 페이지)")
                pages = await _crawl_first_pass(browser, target_url)
                print(f"\n  수집된 페이지 {len(pages)}개")
                for p in pages[:10]:
                    print(f"    - {p['url']}  (forms={len(p['forms'])}개)")
                if len(pages) > 10:
                    print(f"    ... 외 {len(pages) - 10}개")
            await asyncio.sleep(STEP_PAUSE)

            # 로그인 페이지 식별
            _print_step(2, "find_login_page() — 로그인 페이지 식별")
            login_page = find_login_page(pages)
            if login_page is None:
                print("  ❌ 로그인 페이지 미발견")
                print("     → 사이트가 SPA거나, 로그인 폼이 모달/JS로 동적 생성될 수 있음")
                print("     → 브라우저에서 자격증명 입력 페이지 URL을 직접 확인 후")
                print("       그 URL을 target_url로 다시 시도해보세요")
                return
            print(f"  ✓ 로그인 페이지: {login_page['url']}")
            field_names = [f.get('name') for f in login_page['_login_form']['fields']]
            print(f"  ✓ 폼 필드: {field_names}")
            await asyncio.sleep(STEP_PAUSE)

            # 폼 분석
            _print_step(3, "analyze_login_form() — 셀렉터 추론")
            try:
                sel = analyze_login_form(login_page)
            except ValueError as e:
                print(f"  ❌ 폼 분석 실패: {e}")
                return
            print(f"  username: {sel.username}")
            print(f"  password: {sel.password}")
            print(f"  submit:   {sel.submit[:80]}...")
            await asyncio.sleep(STEP_PAUSE)

            # 로그인 시도
            _print_step(4, "perform_login() — 실제 폼 자동 입력")
            print("  → 브라우저 창에서 폼 입력/제출 과정을 직접 관찰하세요")
            cfg = AuthConfig(username=username, password=password)
            result = await perform_login(browser, login_page["url"], sel, cfg)
            await asyncio.sleep(STEP_PAUSE)

            if result.success:
                print(f"  ✓ 로그인 성공!")
                print(f"  ✓ 쿠키 {len(result.cookies)}개 획득:")
                for c in result.cookies[:8]:
                    val = c['value']
                    val_short = val[:30] + "..." if len(val) > 30 else val
                    print(f"      {c['name']}={val_short}  domain={c.get('domain', '?')}")
                if len(result.cookies) > 8:
                    print(f"      ... 외 {len(result.cookies) - 8}개")
            else:
                print(f"  ❌ 로그인 실패: {result.error}")
                print()
                print("  가능한 원인:")
                print("    - 자격증명 오류")
                print("    - reCAPTCHA / 봇 차단")
                print("    - 2FA 요구")
                print("    - 성공 판별 휴리스틱이 사이트 흐름과 맞지 않음")
                print("      → AuthConfig(success_url_pattern=...) 옵션으로 정규식 지정 가능")
                return

            # 인증 상태로 홈페이지 재방문
            _print_step(5, "쿠키 주입 후 홈페이지 재방문 (인증 유지 확인)")
            ctx = await browser.new_context(ignore_https_errors=True)
            await ctx.add_cookies(result.cookies)
            page = await ctx.new_page()
            await page.goto(target_url, wait_until="load", timeout=20_000)
            print(f"  현재 URL: {page.url}")
            print(f"  → 브라우저 창에서 로그인된 상태인지 시각적으로 확인하세요")
            await asyncio.sleep(STEP_PAUSE * 2)
            await ctx.close()

            print()
            print("=" * 72)
            print("  테스트 완료. 5초 후 브라우저 종료합니다...")
            print("=" * 72)
            await asyncio.sleep(5)

        finally:
            await browser.close()


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    target = sys.argv[1].rstrip("/")
    user = sys.argv[2]
    pwd = sys.argv[3]
    manual = "--manual" in sys.argv[4:]
    asyncio.run(main(target, user, pwd, manual=manual))
