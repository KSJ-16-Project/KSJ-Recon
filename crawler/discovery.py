"""
discovery.py — SPA 동적 URL 탐색 모듈

SPA(Single Page Application) 환경에서 정적 HTML 파싱만으로는 발견할 수 없는
URL을 동적으로 탐지한다.

piscovery 참고: piscovery/spider/discovery.py
"""

from __future__ import annotations

from urllib.parse import urljoin

from playwright.async_api import Page

from crawler.parser import _PageParser


# ── 브라우저 주입용 JS 상수 ────────────────────────────────────
# renderer.py 가 page.add_init_script(HISTORY_SHIM) 으로 주입한다.
# pushState / replaceState / popstate / hashchange 를 가로채
# 발생한 URL 을 window.__discovery_urls 배열에 누적한다.
HISTORY_SHIM = """
(() => {
  if (window.__discovery_urls) return;
  window.__discovery_urls = [];

  const _push = history.pushState.bind(history);
  const _replace = history.replaceState.bind(history);

  history.pushState = function(state, title, url) {
    if (url) window.__discovery_urls.push(String(url));
    return _push(state, title, url);
  };
  history.replaceState = function(state, title, url) {
    if (url) window.__discovery_urls.push(String(url));
    return _replace(state, title, url);
  };

  window.addEventListener('popstate',    () => window.__discovery_urls.push(location.href));
  window.addEventListener('hashchange',  () => window.__discovery_urls.push(location.href));
})();
"""


# ── 클릭 시 피해야 할 위험 키워드 ────────────────────────────
# 삭제·결제·로그아웃 등 파괴적 동작을 유발할 수 있는 요소는 클릭하지 않는다.
_BLOCKED_TERMS = [
    "delete", "remove", "logout", "sign out", "signout",
    "purchase", "buy", "checkout", "payment", "pay",
    "삭제", "제거", "로그아웃", "구매", "결제",
]


# ── 지금 사용 가능한 함수 ──────────────────────────────────────

def frame_links(html: str, base_url: str) -> list[str]:
    """
    iframe 내부 HTML을 파싱해서 링크 목록을 반환한다.

    renderer.py 가 page.frames 를 순회하며 각 frame.content() 를
    이 함수에 전달한다.
    """
    parser = _PageParser(base_url)
    parser.feed(html)
    seen: set[str] = set()
    result: list[str] = []
    for url in parser.links:
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result


# ── Playwright page 객체 기반 함수들 ──────────────────────────
# crawler.browser.render 가 page.goto 이후 history_urls / click_walk 호출.

async def history_urls(page: Page, base_url: str) -> list[str]:
    """
    HISTORY_SHIM 이 수집한 URL 목록을 브라우저에서 꺼내온다.
    render.py 의 render() 에서 page.goto() 이후 호출한다.
    """
    raw: list[str] = await page.evaluate("window.__discovery_urls || []")
    seen: set[str] = set()
    result: list[str] = []
    for url in raw:
        abs_url = urljoin(base_url, url)
        if abs_url not in seen:
            seen.add(abs_url)
            result.append(abs_url)
    return result


async def _label(element) -> str:
    """버튼·링크 요소의 표시 텍스트 또는 aria-label 을 반환한다."""
    text = (await element.inner_text()).strip().lower()
    if not text:
        text = (await element.get_attribute("aria-label") or "").strip().lower()
    return text


async def _safe(element) -> bool:
    """
    클릭해도 안전한 요소인지 판단한다.

    다음 조건 중 하나라도 해당하면 False 를 반환한다:
      - disabled 속성이 있다
      - 레이블에 _BLOCKED_TERMS 키워드가 포함된다
      - type="submit" 인 버튼 (폼 제출 방지)
    """
    if await element.is_disabled():
        return False
    label = await _label(element)
    if any(term in label for term in _BLOCKED_TERMS):
        return False
    tag = await element.evaluate("el => el.tagName.toLowerCase()")
    el_type = (await element.get_attribute("type") or "").lower()
    if tag == "button" and el_type == "submit":
        return False
    return True


async def click_walk(page, base_url: str, timeout: int = 120) -> list[str]:
    """
    페이지의 버튼·링크를 클릭하며 새롭게 나타나는 URL을 수집한다.

    동작 순서:
      1. 클릭 가능한 요소(a, button, [role=button]) 목록 수집
      2. _safe() 통과한 요소만 클릭
      3. URL 변경 감지 → history_urls() 로 신규 URL 수집
      4. timeout 초과 시 중단
    """
    import asyncio
    discovered: list[str] = []
    deadline = asyncio.get_event_loop().time() + timeout

    locator = page.locator("a, button, [role=button]")
    count = await locator.count()

    for i in range(count):
        if asyncio.get_event_loop().time() > deadline:
            break
        el = locator.nth(i)
        try:
            if not await _safe(el):
                continue
        except Exception:
            continue
        before_url = page.url
        try:
            await el.click(timeout=3000)
        except Exception:
            # 클릭 실패 시 오버레이 해제 순차 시도
            try:
                await page.keyboard.press("Escape")
            except Exception:
                pass
            try:
                await page.click("body", position={"x": 10, "y": 10}, timeout=1000)
            except Exception:
                pass
            continue
        try:
            await page.wait_for_load_state("networkidle", timeout=3000)
            new_urls = await history_urls(page, base_url)
            discovered.extend(new_urls)
            # 페이지가 이동했으면 원래 페이지로 복귀
            if page.url != before_url:
                await page.goto(before_url)
                await page.wait_for_load_state("networkidle", timeout=3000)
                count = await locator.count()  # 복귀 후 요소 수 재확인
        except Exception:
            continue

    return discovered
