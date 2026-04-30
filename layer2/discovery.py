"""
discovery.py — SPA 동적 URL 탐색 모듈

SPA(Single Page Application) 환경에서 정적 HTML 파싱만으로는 발견할 수 없는
URL을 동적으로 탐지한다.

  - frame_links, HISTORY_SHIM : 지금 사용 가능
  - history_urls, click_walk  : renderer.py (Phase 5) 구현 후 주석 해제

piscovery 참고: piscovery/spider/discovery.py
"""

from __future__ import annotations

from urllib.parse import urljoin
from crawler.parser import _PageParser   # iframe HTML 파싱에 재사용


# ── 브라우저 주입용 JS 상수 ────────────────────────────────────
# renderer.py 가 page.add_init_script(HISTORY_SHIM) 으로 주입한다.
# pushState / replaceState / popstate / hashchange 를 가로채
# 발생한 URL 을 window.__piscovery_urls 배열에 누적한다.
HISTORY_SHIM = """
(() => {
  if (window.__piscovery_urls) return;
  window.__piscovery_urls = [];

  const _push = history.pushState.bind(history);
  const _replace = history.replaceState.bind(history);

  history.pushState = function(state, title, url) {
    if (url) window.__piscovery_urls.push(String(url));
    return _push(state, title, url);
  };
  history.replaceState = function(state, title, url) {
    if (url) window.__piscovery_urls.push(String(url));
    return _replace(state, title, url);
  };

  window.addEventListener('popstate',    () => window.__piscovery_urls.push(location.href));
  window.addEventListener('hashchange',  () => window.__piscovery_urls.push(location.href));
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


# ── renderer.py (Phase 5) 구현 후 주석 해제 ───────────────────
# 아래 함수들은 Playwright page 객체가 필요하다.
# renderer.py 에서 from crawler.discovery import history_urls, click_walk 로 호출한다.

# async def history_urls(page, base_url: str) -> list[str]:
#     """
#     HISTORY_SHIM 이 수집한 URL 목록을 브라우저에서 꺼내온다.
#     renderer.py 의 render() 에서 page.goto() 이후 호출한다.
#
#     page.evaluate("window.__piscovery_urls || []") 로 JS 변수를 읽는다.
#     """
#     raw: list[str] = await page.evaluate("window.__piscovery_urls || []")
#     seen: set[str] = set()
#     result: list[str] = []
#     for url in raw:
#         abs_url = urljoin(base_url, url)
#         if abs_url not in seen:
#             seen.add(abs_url)
#             result.append(abs_url)
#     return result


# async def _label(element) -> str:
#     """버튼·링크 요소의 표시 텍스트 또는 aria-label 을 반환한다."""
#     text = (await element.inner_text()).strip().lower()
#     if not text:
#         text = (await element.get_attribute("aria-label") or "").strip().lower()
#     return text


# async def _safe(element) -> bool:
#     """
#     클릭해도 안전한 요소인지 판단한다.
#
#     다음 조건 중 하나라도 해당하면 False 를 반환한다:
#       - disabled 속성이 있다
#       - 레이블에 _BLOCKED_TERMS 키워드가 포함된다
#       - type="submit" 인 버튼 (폼 제출 방지)
#     """
#     if await element.is_disabled():
#         return False
#     label = await _label(element)
#     if any(term in label for term in _BLOCKED_TERMS):
#         return False
#     tag = await element.evaluate("el => el.tagName.toLowerCase()")
#     el_type = (await element.get_attribute("type") or "").lower()
#     if tag == "button" and el_type == "submit":
#         return False
#     return True


# async def click_walk(page, base_url: str, max_clicks: int = 20) -> list[str]:
#     """
#     페이지의 버튼·링크를 클릭하며 새롭게 나타나는 URL을 수집한다.
#
#     동작 순서:
#       1. 클릭 가능한 요소(a, button, [role=button]) 목록 수집
#       2. _safe() 통과한 요소만 클릭
#       3. URL 변경 감지 → history_urls() 로 신규 URL 수집
#       4. max_clicks 초과 시 중단
#     """
#     discovered: list[str] = []
#     clicked = 0
#
#     elements = await page.query_selector_all("a, button, [role=button]")
#     for el in elements:
#         if clicked >= max_clicks:
#             break
#         if not await _safe(el):
#             continue
#         try:
#             await el.click(timeout=3000)
#             await page.wait_for_load_state("networkidle", timeout=3000)
#             new_urls = await history_urls(page, base_url)
#             discovered.extend(new_urls)
#             clicked += 1
#         except Exception:
#             continue
#
#     return discovered
