from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from urllib.parse import urljoin, urlparse, urlunparse

from playwright.async_api import Browser

import ksj_login
from crawler.browser import BrowserManager, RawPageData, render
from crawler.models import CrawlResult, CrawlerConfig, EndpointHint, PageSnapshot
from crawler.parser import (
    detect_csr_framework,
    detect_render_type,
    detect_technologies,
    extract_comments,
    extract_endpoints,
    extract_forms,
    extract_links,
    extract_manifest_url,
    extract_routes_from_js,
    extract_scripts,
    extract_url_params,
)
from crawler.sitemap import fetch_robots, fetch_sitemap, fetch_url


async def crawl_target(
    config: CrawlerConfig,
    *,
    browser: Browser | None = None,
) -> CrawlResult:
    own_browser = browser is None
    bm: BrowserManager | None = None
    if own_browser:
        bm = BrowserManager(headless=True)
        await bm.__aenter__()
        browser = bm.browser
    assert browser is not None

    try:
        return await _crawl_with_browser(browser, config)
    finally:
        if own_browser and bm is not None:
            await bm.__aexit__(None, None, None)


async def _crawl_with_browser(browser: Browser, config: CrawlerConfig) -> CrawlResult:
    result = CrawlResult(target_url=_normalise_url(config.target_url, config.target_url))

    public_pages, sitemap_urls, robots_info, errors = await _crawl_once(
        browser,
        config,
        seeds=[config.target_url],
        phase="public",
    )
    result.public_pages = public_pages
    result.sitemap_urls = sitemap_urls
    result.robots_info = robots_info
    result.errors.extend(errors)

    if ksj_login.has_credentials():
        auth_result = await ksj_login.get_session()
        if auth_result.success:
            auth_pages, _, _, auth_errors = await _crawl_once(
                browser,
                config,
                seeds=[config.target_url],
                phase="authenticated",
                cookies=auth_result.cookies,
            )
            public_signatures = {(p.url, p.status) for p in public_pages}
            result.authenticated_pages = [
                p for p in auth_pages if (p.url, p.status) not in public_signatures
            ]
            result.errors.extend(auth_errors)

    result.endpoint_hints = _dedupe_endpoints(
        hint for page in result.pages for hint in page.endpoint_hints
    )
    result.external_endpoint_hints = _dedupe_endpoints(
        hint for page in result.pages for hint in page.external_endpoint_hints
    )
    return result


async def _crawl_once(
    browser: Browser,
    config: CrawlerConfig,
    *,
    seeds: list[str],
    phase: str,
    cookies: list[dict] | None = None,
    local_storage: dict | None = None,
    session_storage: dict | None = None,
) -> tuple[list[PageSnapshot], list[str], dict, list[str]]:
    render_concurrency = max(1, min(config.concurrency, 4))
    semaphore = asyncio.Semaphore(render_concurrency)
    visited: set[str] = set()
    pages: list[PageSnapshot] = []
    errors: list[str] = []
    signatures = _SignatureCounter(config.query_variants_limit)
    queue: deque[tuple[str, int]] = deque((_normalise_url(config.target_url, seed), 0) for seed in seeds)

    robots_info = {"disallowed": [], "sitemaps": []}
    sitemap_urls: list[str] = []
    try:
        disallowed, sitemaps = await fetch_robots(config.target_url)
        robots_info = {"disallowed": disallowed, "sitemaps": sitemaps}
        sitemap_seeds = sitemaps or [urljoin(_base_url(config.target_url), "/sitemap.xml")]
        for sitemap in sitemap_seeds[:5]:
            for url in await fetch_sitemap(sitemap):
                full = _normalise_url(config.target_url, url)
                if _is_in_scope(full, config.target_url):
                    sitemap_urls.append(full)
                    queue.append((full, 1))
    except Exception as exc:
        errors.append(f"{phase}: sitemap discovery failed: {exc}")

    js_cache: dict[str, str] = {}
    start = time.monotonic()

    while queue and len(pages) < config.max_pages:
        if _budget_exceeded(start, config.scan_budget):
            errors.append(f"{phase}: scan budget exceeded")
            break

        batch: list[tuple[str, int]] = []
        remaining = max(0, config.max_pages - len(pages))
        while queue and len(batch) < min(render_concurrency, remaining):
            raw_url, depth = queue.popleft()
            url = _normalise_url(config.target_url, raw_url)
            if _admit(url, depth, config, visited, signatures):
                batch.append((url, depth))

        if not batch:
            break

        tasks = [
            _render_one(
                browser,
                config,
                url,
                depth,
                semaphore,
                cookies=cookies,
                local_storage=local_storage,
                session_storage=session_storage,
            )
            for url, depth in batch
        ]
        rendered = await asyncio.gather(*tasks, return_exceptions=True)

        for item in rendered:
            if isinstance(item, Exception):
                errors.append(f"{phase}: render failed: {item}")
                continue
            if item is None:
                continue
            if len(pages) >= config.max_pages:
                break

            page = _snapshot_from_raw(item[0], item[1], config.target_url)
            await _enrich_from_scripts(page, config, js_cache)
            pages.append(page)

            if page.depth < config.max_depth:
                for link in [*page.links, *page.routes]:
                    full = _normalise_url(config.target_url, link)
                    if _is_in_scope(full, config.target_url) and full not in visited:
                        queue.append((full, page.depth + 1))

                manifest_url = extract_manifest_url(page.rendered_html or page.raw_html, page.url)
                for manifest_link in await _manifest_links(manifest_url):
                    full = _normalise_url(config.target_url, manifest_link)
                    if _is_in_scope(full, config.target_url) and full not in visited:
                        queue.append((full, page.depth + 1))

    return pages, _dedupe_strings(sitemap_urls), robots_info, errors


async def _render_one(
    browser: Browser,
    config: CrawlerConfig,
    url: str,
    depth: int,
    semaphore: asyncio.Semaphore,
    *,
    cookies: list[dict] | None,
    local_storage: dict | None,
    session_storage: dict | None,
) -> tuple[RawPageData, int] | None:
    async with semaphore:
        raw = await render(
            browser,
            url,
            timeout=config.timeout,
            render_wait=config.render_wait,
            block_heavy_resources=config.block_heavy_resources,
            extra_headers=config.headers,
            cookies=cookies,
            local_storage=local_storage,
            session_storage=session_storage,
        )
        if raw is None:
            return None
        return raw, depth


def _snapshot_from_raw(raw: RawPageData, depth: int, target_url: str) -> PageSnapshot:
    html = raw.rendered_html or raw.raw_html
    all_endpoint_hints = [
        EndpointHint(
            url=x.url,
            method=x.method,
            source=x.resource_type or "xhr",
            page_url=raw.url,
        )
        for x in raw.xhr_list
    ]
    all_endpoint_hints.extend(
        EndpointHint(url=w.url, method="WS", source="websocket", page_url=raw.url)
        for w in raw.ws_list
    )
    # Keep external observations separate so core only consumes in-scope endpoints.

    endpoint_hints = [
        hint for hint in all_endpoint_hints
        if _is_endpoint_in_scope(hint.url, target_url)
    ]
    external_endpoint_hints = [
        hint for hint in all_endpoint_hints
        if not _is_endpoint_in_scope(hint.url, target_url)
    ]
    scoped_xhr_list = [
        xhr for xhr in raw.xhr_list
        if _is_endpoint_in_scope(xhr.url, target_url)
    ]
    scoped_ws_list = [
        ws for ws in raw.ws_list
        if _is_endpoint_in_scope(ws.url, target_url)
    ]

    snapshot = PageSnapshot(
        url=raw.url,
        depth=depth,
        status=raw.status,
        raw_html=raw.raw_html,
        rendered_html=raw.rendered_html,
        links=_scope_urls(extract_links(html, raw.url), target_url),
        scripts=_scope_urls(extract_scripts(html, raw.url), target_url),
        forms=extract_forms(html, raw.url),
        technologies=detect_technologies(html, raw.response_headers),
        render_type=detect_render_type(raw.raw_html, raw.rendered_html),
        xhr_list=scoped_xhr_list,
        ws_list=scoped_ws_list,
        endpoint_hints=endpoint_hints,
        external_endpoint_hints=external_endpoint_hints,
        request_headers=raw.request_headers,
        response_headers=raw.response_headers,
        cookies=raw.cookies,
        comments=extract_comments(html),
        url_params=extract_url_params(raw.url),
        csr_framework=detect_csr_framework(html) or "",
    )
    snapshot.routes = _scope_urls(
        [*snapshot.routes, *getattr(raw, "discovered_urls", [])],
        target_url,
    )
    return snapshot


async def _enrich_from_scripts(
    page: PageSnapshot,
    config: CrawlerConfig,
    js_cache: dict[str, str],
) -> None:
    routes: set[str] = set(page.routes)
    hints: list[EndpointHint] = list(page.endpoint_hints)
    external_hints: list[EndpointHint] = list(page.external_endpoint_hints)

    for script_url in page.scripts[:10]:
        if not _is_in_scope(script_url, config.target_url):
            continue
        if script_url not in js_cache:
            status, body = await fetch_url(script_url)
            js_cache[script_url] = body if status == 200 else ""
        js_body = js_cache[script_url]
        if not js_body:
            continue

        for route in extract_routes_from_js(js_body):
            full = _normalise_url(config.target_url, urljoin(page.url, route))
            if _is_in_scope(full, config.target_url):
                routes.add(full)

        for endpoint in extract_endpoints(js_body):
            full = _normalise_url(config.target_url, urljoin(page.url, endpoint))
            hint = EndpointHint(
                url=full,
                method="GET",
                source="js-static",
                page_url=page.url,
            )
            if _is_endpoint_in_scope(full, config.target_url):
                hints.append(hint)
            else:
                external_hints.append(hint)

    page.routes = sorted(routes)
    page.endpoint_hints = _dedupe_endpoints(hints)
    page.external_endpoint_hints = _dedupe_endpoints(external_hints)


async def _manifest_links(manifest_url: str) -> list[str]:
    if not manifest_url:
        return []
    status, body = await fetch_url(manifest_url)
    if status != 200 or not body:
        return []
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []

    out: list[str] = []
    for key in ("start_url", "scope"):
        val = data.get(key)
        if isinstance(val, str) and val:
            out.append(urljoin(manifest_url, val))
    for shortcut in data.get("shortcuts", []) or []:
        if isinstance(shortcut, dict) and isinstance(shortcut.get("url"), str):
            out.append(urljoin(manifest_url, shortcut["url"]))
    return out


def _admit(
    url: str,
    depth: int,
    config: CrawlerConfig,
    visited: set[str],
    signatures: "_SignatureCounter",
) -> bool:
    if url in visited:
        return False
    if depth > config.max_depth:
        return False
    if _path_too_deep(url, config.path_depth_limit):
        return False
    if signatures.see(url):
        return False
    visited.add(url)
    return True


def _normalise_url(base: str, href: str) -> str:
    parsed = urlparse(urljoin(base, href))
    path = parsed.path.rstrip("/") or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, ""))


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _is_in_scope(url: str, target_url: str) -> bool:
    parsed = urlparse(url)
    target = urlparse(target_url)
    return parsed.scheme in ("http", "https") and parsed.netloc == target.netloc


def _is_endpoint_in_scope(url: str, target_url: str) -> bool:
    parsed = urlparse(urljoin(target_url, url))
    target = urlparse(target_url)
    return parsed.scheme in ("http", "https", "ws", "wss") and parsed.netloc == target.netloc


def _scope_urls(urls, target_url: str) -> list[str]:
    return _dedupe_strings(
        url for url in urls
        if _is_in_scope(_normalise_url(target_url, url), target_url)
    )


def _path_too_deep(url: str, limit: int) -> bool:
    if limit <= 0:
        return False
    return len([p for p in urlparse(url).path.split("/") if p]) > limit


def _budget_exceeded(start: float, budget: int) -> bool:
    return budget > 0 and (time.monotonic() - start) >= budget


def _dedupe_strings(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _dedupe_endpoints(values) -> list[EndpointHint]:
    out: list[EndpointHint] = []
    seen: set[tuple[str, str, str]] = set()
    for hint in values:
        key = (hint.method.upper(), hint.url, hint.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(hint)
    return out


class _SignatureCounter:
    def __init__(self, limit: int):
        self.limit = limit
        self.counts: dict[tuple[str, tuple[str, ...]], int] = {}

    def see(self, url: str) -> bool:
        if self.limit <= 0:
            return False
        parsed = urlparse(url)
        keys = tuple(sorted(part.split("=", 1)[0] for part in parsed.query.split("&") if part))
        sig = (parsed.path, keys)
        self.counts[sig] = self.counts.get(sig, 0) + 1
        return self.counts[sig] > self.limit
