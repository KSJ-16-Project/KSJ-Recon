"""post_scanner.py — 폼 제출 / submit 버튼 클릭 / API 직접 POST 수집"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs, urlparse

import aiohttp
from playwright.async_api import Browser, Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError

from crawler.browser.browser import XHRRecord
from crawler.models import CrawlerConfig, EndpointHint, PageSnapshot

_OBSERVED_RESOURCE_TYPES = {"xhr", "fetch", "eventsource"}
_BODY_LIMIT = 4096

_TEST_VALUES: dict[str, str] = {
    "text":     "test",
    "email":    "test@example.com",
    "number":   "1",
    "tel":      "01012345678",
    "search":   "test",
    "url":      "http://example.com",
    "":         "test",
}


async def scan_post_requests(
    browser: Browser,
    snapshot: PageSnapshot,
    config: CrawlerConfig,
    cookies: list[dict] | None = None,
) -> list[EndpointHint]:
    """
    1. 폼 action URL 직접 수집 (전통적 form POST 포함)
    2. 폼 직접 제출 (submit 버튼 클릭 포함) → 발생하는 XHR 캡처
    3. 발견된 POST/PUT/DELETE 엔드포인트에 직접 HTTP 요청
    """
    hints: list[EndpointHint] = []
    hints.extend(_collect_form_actions(snapshot, config))
    hints.extend(await _submit_forms(browser, snapshot, config, cookies))
    hints.extend(await _probe_post_endpoints(snapshot, config, cookies))
    return hints


def _collect_form_actions(snapshot: PageSnapshot, config: CrawlerConfig) -> list[EndpointHint]:
    """폼 action URL을 EndpointHint로 직접 수집한다 (XHR 없이 페이지 이동하는 전통적 form 포함)."""
    hints: list[EndpointHint] = []
    for form in snapshot.forms:
        if not form.action:
            continue
        if not _is_in_scope(form.action, config.target_url):
            continue
        method = form.method.upper() or "GET"
        params = {f.name: f.value or _TEST_VALUES.get(f.type or "", "test")
                  for f in form.fields if f.name}
        hints.append(EndpointHint(
            url=form.action,
            method=method,
            source="form-action",
            page_url=snapshot.url,
            params=params,
        ))
    return hints


async def _submit_forms(
    browser: Browser,
    snapshot: PageSnapshot,
    config: CrawlerConfig,
    cookies: list[dict] | None,
) -> list[EndpointHint]:
    """별도 컨텍스트에서 페이지를 다시 열어 폼을 제출하고 발생하는 XHR을 캡처한다.
    action 속성이 없는 JS 동적 폼이 있을 때만 실행한다."""
    dynamic_forms = [f for f in snapshot.forms if not f.action]
    if not dynamic_forms:
        return []

    hints: list[EndpointHint] = []
    ctx = None
    try:
        ctx = await browser.new_context(ignore_https_errors=True)
        if cookies:
            try:
                await ctx.add_cookies(cookies)
            except PlaywrightError:
                pass

        page = await ctx.new_page()
        xhr_captured: list[XHRRecord] = []

        def on_request(req):
            if req.resource_type not in _OBSERVED_RESOURCE_TYPES:
                return
            try:
                post_data = req.post_data or ""
            except Exception:
                post_data = ""
            xhr_captured.append(XHRRecord(
                url=req.url,
                method=req.method,
                resource_type=req.resource_type,
                post_data=post_data[:_BODY_LIMIT],
                params=_parse_params(req.url, post_data),
            ))

        page.on("request", on_request)

        try:
            await page.goto(snapshot.url, wait_until="domcontentloaded", timeout=20_000)
        except PlaywrightError:
            return []

        form_locator = page.locator("form")
        form_count = await form_locator.count()

        for i in range(form_count):
            form = form_locator.nth(i)

            # 로그인 폼(password 필드 있음)은 ksj_login이 처리하므로 건너뜀
            try:
                if await form.locator("input[type='password']").count() > 0:
                    continue
            except PlaywrightError:
                continue

            # 입력 필드 채우기
            inputs = form.locator(
                "input:not([type='hidden']):not([type='submit'])"
                ":not([type='button']):not([type='checkbox']):not([type='radio'])"
            )
            try:
                input_count = await inputs.count()
            except PlaywrightError:
                continue

            for j in range(input_count):
                inp = inputs.nth(j)
                try:
                    field_type = (await inp.get_attribute("type") or "text").lower()
                    await inp.fill(_TEST_VALUES.get(field_type, "test"), timeout=2_000)
                except PlaywrightError:
                    continue

            # 제출 전 XHR 카운트 기록
            before_count = len(xhr_captured)
            before_url = page.url

            # 제출 시도: submit 버튼 클릭 → Enter 폴백
            try:
                submit = form.locator(
                    "button[type='submit'], input[type='submit'], button"
                ).first
                await submit.click(timeout=3_000)
            except PlaywrightError:
                try:
                    await inputs.first.press("Enter", timeout=2_000)
                except PlaywrightError:
                    continue

            try:
                await page.wait_for_load_state("networkidle", timeout=3_000)
            except (PlaywrightTimeoutError, PlaywrightError):
                pass

            # 제출 후 발생한 새 XHR → EndpointHint
            for xhr in xhr_captured[before_count:]:
                if _is_in_scope(xhr.url, config.target_url):
                    hints.append(EndpointHint(
                        url=xhr.url,
                        method=xhr.method,
                        source="form-submit",
                        page_url=snapshot.url,
                        params=xhr.params,
                    ))

            # 페이지가 이동했으면 원래 페이지로 복귀
            if page.url != before_url:
                try:
                    await page.goto(snapshot.url, wait_until="domcontentloaded", timeout=10_000)
                except PlaywrightError:
                    break

    except PlaywrightError:
        pass
    finally:
        if ctx is not None:
            try:
                await ctx.close()
            except PlaywrightError:
                pass

    return hints


async def _probe_post_endpoints(
    snapshot: PageSnapshot,
    config: CrawlerConfig,
    cookies: list[dict] | None,
) -> list[EndpointHint]:
    """스냅샷의 endpoint_hints 중 POST/PUT/DELETE를 직접 HTTP 요청으로 탐침한다."""
    targets = [
        h for h in snapshot.endpoint_hints
        if h.method.upper() not in ("GET", "WS", "WEBSOCKET")
        and _is_in_scope(h.url, config.target_url)
    ]
    if not targets:
        return []

    cookie_header = "; ".join(
        f"{c['name']}={c['value']}" for c in (cookies or []) if c.get("name")
    )
    base_headers: dict[str, str] = {"Content-Type": "application/json"}
    if cookie_header:
        base_headers["Cookie"] = cookie_header

    timeout = aiohttp.ClientTimeout(total=5)

    async def _probe_one(session, hint: EndpointHint):
        body = hint.params or {}
        try:
            async with session.request(
                method=hint.method,
                url=hint.url,
                json=body if body else None,
                timeout=timeout,
                ssl=False,
            ):
                return EndpointHint(
                    url=hint.url,
                    method=hint.method,
                    source="api-direct",
                    page_url=snapshot.url,
                    params=body,
                )
        except Exception:
            return None

    async with aiohttp.ClientSession(headers=base_headers) as session:
        results = await asyncio.gather(*(_probe_one(session, h) for h in targets))
    hints = [r for r in results if r is not None]

    return hints


def _parse_params(url: str, post_data: str) -> dict:
    params: dict = {}
    qs = urlparse(url).query
    if qs:
        parsed = parse_qs(qs)
        params.update({k: v[0] if len(v) == 1 else v for k, v in parsed.items()})
    if post_data:
        try:
            body = json.loads(post_data)
            if isinstance(body, dict):
                params.update(body)
        except (json.JSONDecodeError, ValueError):
            try:
                parsed = parse_qs(post_data)
                params.update({k: v[0] if len(v) == 1 else v for k, v in parsed.items()})
            except Exception:
                pass
    return params


def _is_in_scope(url: str, target_url: str) -> bool:
    parsed = urlparse(url)
    target = urlparse(target_url)
    return parsed.scheme in ("http", "https") and parsed.netloc == target.netloc
