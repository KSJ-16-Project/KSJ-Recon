"""
sitemap.py — robots.txt & 사이트맵 파싱 모듈

크롤링 시작 전에 호출하여 시드 URL과 제한 경로를 확보한다.
네트워크 요청은 모두 asyncio.to_thread() 로 비동기 처리한다.
piscovery 참고: piscovery/spider/sitemap.py
"""

from __future__ import annotations

import re
import urllib.request
import asyncio
from urllib.parse import urljoin, urlparse


_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# 보안 정찰에서 존재 여부를 확인하는 공개 표준 파일 목록
_SECURITY_FILES = [
    "/.well-known/security.txt",
    "/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]


def _base_url(target_url: str) -> str:
    """target_url 에서 scheme + host 만 추출한다. (예: https://example.com)"""
    parsed = urlparse(target_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _get(url: str, timeout: int = 10) -> tuple[int, str]:
    """
    urllib 로 GET 요청을 보내고 (상태코드, 응답 본문) 을 반환한다.

    [학습 포인트] asyncio.to_thread
      urllib.request.urlopen 은 블로킹 함수다.
      비동기 코드 안에서 그냥 호출하면 이벤트 루프 전체가 멈춘다.
      asyncio.to_thread() 는 블로킹 함수를 별도 스레드에서 실행해
      이벤트 루프가 다른 작업을 계속 처리할 수 있게 해준다.
    """
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


async def fetch_url(url: str, timeout: int = 10) -> tuple[int, str]:
    """URL 에 GET 요청을 보내고 (상태코드, 응답 본문) 을 반환한다."""
    return await asyncio.to_thread(_get, url, timeout)


async def fetch_robots(target_url: str) -> tuple[list[str], list[str]]:
    """
    /robots.txt 를 파싱해 (disallowed 경로 목록, sitemap URL 목록) 을 반환한다.

    disallowed 경로: crawler.py 가 해당 경로를 스킵하는 데 사용
    sitemap URL:     fetch_sitemap() 의 시드로 사용
    """
    robots_url = urljoin(_base_url(target_url), "/robots.txt")
    status, body = await fetch_url(robots_url)

    if status != 200 or not body:
        return [], []

    disallowed: list[str] = []
    sitemaps: list[str] = []

    for line in body.splitlines():
        line = line.strip()
        lower = line.lower()
        if lower.startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
        elif lower.startswith("sitemap:"):
            url = line.split(":", 1)[1].strip()
            if url:
                sitemaps.append(url)

    return disallowed, sitemaps


async def fetch_sitemap(sitemap_url: str, _checked: set[str] | None = None,
                        limit: int = 5) -> list[str]:
    """
    sitemap.xml 을 파싱해 URL 목록을 반환한다.
    중첩 sitemap index 는 재귀적으로 처리하며 최대 limit 개 파일까지 확인한다.

    [학습 포인트] 재귀 + 중복 방지
      _checked 집합에 이미 처리한 sitemap URL 을 기록해
      무한 재귀와 중복 요청을 방지한다.
    """
    if _checked is None:
        _checked = set()

    if sitemap_url in _checked or len(_checked) >= limit:
        return []
    _checked.add(sitemap_url)

    status, body = await fetch_url(sitemap_url)
    if status != 200 or not body:
        return []

    urls: list[str] = []

    # <sitemap><loc>...</loc></sitemap> → 중첩 sitemap index
    nested = re.findall(r"<sitemap>\s*<loc>([^<]+)</loc>", body, re.IGNORECASE)
    for nested_url in nested:
        child_urls = await fetch_sitemap(nested_url.strip(), _checked, limit)
        urls.extend(child_urls)

    # <url><loc>...</loc></url> → 실제 페이지 URL
    page_locs = re.findall(r"<url>\s*<loc>([^<]+)</loc>", body, re.IGNORECASE)
    urls.extend(loc.strip() for loc in page_locs)

    # 중복 제거 (순서 유지)
    seen: set[str] = set()
    result: list[str] = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result


# [core 옵션에 따라 실행 여부 결정] 결과는 LLM 에 전달하여 내용의 보안 가치 판단
async def check_security_files(target_url: str) -> dict[str, str]:
    """
    보안 정찰 표준 파일의 존재 여부와 내용을 반환한다.

    반환값: {파일 경로: 응답 본문}  (404 등 실패한 파일은 포함하지 않는다)
    """
    base = _base_url(target_url)
    found: dict[str, str] = {}

    for path in _SECURITY_FILES:
        status, body = await fetch_url(urljoin(base, path))
        if status == 200 and body:
            found[path] = body

    return found
