import asyncio
import re

from playwright.async_api import (
    Browser,
    Error as PlaywrightError,
    TimeoutError as PlaywrightTimeoutError,
)

from .browser import BrowserManager, RawPageData, WSRecord, XHRRecord
from layer2.discovery import HISTORY_SHIM, history_urls, click_walk


_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

_BLOCK_RESOURCE_TYPES = {"font", "image", "media"}
_OBSERVED_RESOURCE_TYPES = {"xhr", "fetch", "eventsource"}

# resource_type으로 걸리지 않는 대용량 바이너리 확장자 (예: .glb 3D 모델)
_BLOCK_EXTENSIONS = {".glb", ".gltf", ".wasm", ".bin", ".mp4", ".webm", ".mp3", ".ogg"}

_BODY_MIMES = (
    "application/json",
    "application/x-ndjson",
    "application/ld+json",
    "text/",
    "application/javascript",
    "application/xml",
    "application/graphql",
)

_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)

_BODY_LIMIT = 4096          # 응답 body 캡처 최대 크기 (bytes)
_WS_FRAME_LIMIT = 1024      # WebSocket 프레임 캡처 최대 크기 (bytes)
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024


def _redact(text: str) -> str:
    return _JWT_RE.sub("[REDACTED:JWT]", text)


def _is_body_capturable(mime: str) -> bool:
    if not mime:
        return False
    low = mime.lower()
    return any(low.startswith(p) for p in _BODY_MIMES) or "+json" in low


async def _block_heavy(route):
    try:
        req = route.request
        if req.resource_type in _BLOCK_RESOURCE_TYPES:
            await route.abort()
            return
        path = req.url.split("?")[0].lower()
        if any(path.endswith(ext) for ext in _BLOCK_EXTENSIONS):
            await route.abort()
            return
    except PlaywrightError:
        pass
    try:
        await route.continue_()
    except PlaywrightError:
        pass


async def render(
    browser: Browser,
    url: str,
    *,
    timeout: int = 30,
    render_wait: int = 0,
    block_heavy_resources: bool = True,
    extra_headers: dict | None = None,
) -> RawPageData | None:
    """URL을 Playwright로 렌더링하고 RawPageData를 반환한다.

    파싱·분석은 하지 않는다 — 순수 네트워크/렌더링 데이터만 수집.
    """
    try:
        return await asyncio.wait_for(
            _run(browser, url, timeout, render_wait, block_heavy_resources, extra_headers or {}),
            timeout=timeout + 10,
        )
    except asyncio.TimeoutError:
        return None


async def _run(
    browser: Browser,
    url: str,
    timeout: int,
    render_wait: int,
    block_heavy_resources: bool,
    extra_headers: dict,
) -> RawPageData | None:
    ctx = await browser.new_context(
        user_agent=_UA,
        ignore_https_errors=True,
        extra_http_headers=extra_headers,
    )

    try:
        if block_heavy_resources:
            try:
                await ctx.route("**/*", _block_heavy)
            except PlaywrightError:
                pass

        await ctx.add_init_script(HISTORY_SHIM)
        page = await ctx.new_page()

        xhr_list: list[XHRRecord] = []
        ws_list: list[WSRecord] = []
        body_budget = {"used": 0}

        # ── 요청 인터셉트 ──────────────────────────────────────────────
        def on_request(req):
            if req.resource_type not in _OBSERVED_RESOURCE_TYPES:
                return
            path = req.url.split("?")[0].lower()
            if any(path.endswith(ext) for ext in _BLOCK_EXTENSIONS):
                return
            try:
                post_data = req.post_data or ""
            except Exception:
                post_data = ""
            xhr_list.append(XHRRecord(
                url=req.url,
                method=req.method,
                resource_type=req.resource_type,
                post_data=post_data[:_BODY_LIMIT],
            ))

        page.on("request", on_request)

        # ── 응답 인터셉트 ──────────────────────────────────────────────
        async def on_response(resp):
            try:
                if resp.request.resource_type not in _OBSERVED_RESOURCE_TYPES:
                    return
                try:
                    headers = {k.lower(): v for k, v in (await resp.all_headers()).items()}
                except PlaywrightError:
                    headers = {}

                mime = (headers.get("content-type") or "").split(";")[0].strip().lower()
                body_preview = ""

                if _is_body_capturable(mime) and body_budget["used"] < _MAX_RESPONSE_BYTES:
                    try:
                        raw_body = await resp.body()
                    except PlaywrightError:
                        raw_body = b""
                    if raw_body:
                        chunk = raw_body[:_BODY_LIMIT]
                        body_preview = _redact(chunk.decode("utf-8", errors="replace"))
                        body_budget["used"] += len(chunk)

                # XHRRecord에 응답 정보 보완 (url 기준으로 마지막 것 갱신)
                for rec in reversed(xhr_list):
                    if rec.url == resp.url and rec.status_code == 0:
                        rec.status_code = resp.status
                        rec.response_headers = headers
                        rec.body_preview = body_preview
                        rec.mime = mime
                        break
            except Exception:
                pass

        page.on("response", on_response)

        # ── WebSocket 인터셉트 ─────────────────────────────────────────
        def on_websocket(ws):
            rec = WSRecord(url=ws.url)
            ws_list.append(rec)
            sent_budget = {"left": _WS_FRAME_LIMIT}
            recv_budget = {"left": _WS_FRAME_LIMIT}

            def _payload(p):
                return p.get("payload") if isinstance(p, dict) else p

            def _record(payload, budget, attr):
                if not isinstance(payload, str) or budget["left"] <= 0:
                    return
                chunk = payload[:budget["left"]]
                budget["left"] -= len(chunk)
                cur = getattr(rec, attr) or ""
                setattr(rec, attr, (cur + _redact(chunk))[:_WS_FRAME_LIMIT])

            ws.on("framesent", lambda p: _record(_payload(p), sent_budget, "sent_preview"))
            ws.on("framereceived", lambda p: _record(_payload(p), recv_budget, "received_preview"))

            def on_close(*args):
                rec.closed = True
                if args and isinstance(args[0], int):
                    rec.close_code = args[0]

            ws.on("close", on_close)

        try:
            page.on("websocket", on_websocket)
        except (PlaywrightError, AttributeError):
            pass

        # ── 페이지 이동 ────────────────────────────────────────────────
        status = 0
        resp_headers: dict = {}
        raw_html = ""
        rendered_html = ""

        response = None
        try:
            response = await page.goto(url, timeout=timeout * 1000, wait_until="load")
        except PlaywrightTimeoutError:
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=timeout * 1000)
            except PlaywrightTimeoutError:
                pass
        except PlaywrightError:
            return None

        if render_wait > 0:
            try:
                await page.wait_for_timeout(render_wait)
            except PlaywrightError:
                pass

        if response is not None:
            status = response.status
            try:
                resp_headers = {k.lower(): v for k, v in (await response.all_headers()).items()}
            except PlaywrightError:
                resp_headers = {}
            try:
                body = await response.body()
                if 0 < _MAX_RESPONSE_BYTES < len(body):
                    raw_html = ""
                else:
                    raw_html = body.decode("utf-8", errors="replace")
            except PlaywrightError:
                raw_html = ""

        try:
            rendered_html = await page.content()
        except PlaywrightError:
            rendered_html = ""

        # ── URL 탐색 (discovery) ───────────────────────────────────────
        discovered_urls: list[str] = []
        try:
            from_history = await history_urls(page, url)
            from_clicks = await click_walk(page, url)
            seen_d: set[str] = set()
            for u in from_history + from_clicks:
                if u not in seen_d:
                    seen_d.add(u)
                    discovered_urls.append(u)
        except Exception:
            pass

        # ── 쿠키 수집 ─────────────────────────────────────────────────
        try:
            jar = await ctx.cookies([url])
            cookies = [f"{c['name']}={c['value']}" for c in jar]
        except PlaywrightError:
            cookies = _parse_cookies_from_header(resp_headers)

    finally:
        try:
            await ctx.close()
        except PlaywrightError:
            pass

    if status == 0 and not rendered_html and not raw_html:
        return None

    req_headers = {"User-Agent": _UA, **extra_headers}

    return RawPageData(
        url=url,
        status=status,
        request_headers=req_headers,
        response_headers=resp_headers,
        raw_html=raw_html,
        rendered_html=rendered_html,
        xhr_list=xhr_list,
        ws_list=ws_list,
        cookies=cookies,
        discovered_urls=discovered_urls,
    )


def _parse_cookies_from_header(headers: dict) -> list[str]:
    cookies: list[str] = []
    raw = headers.get("set-cookie", "")
    if not raw:
        return cookies
    for part in re.split(r",\s*(?=[A-Za-z_\-]+=)", raw):
        part = part.strip()
        if not part:
            continue
        pair = part.split(";")[0].strip()
        if "=" in pair:
            cookies.append(pair)
    return cookies


async def probe() -> tuple[bool, str]:
    """Playwright + Chromium 동작 여부를 빠르게 검증한다."""
    try:
        async with BrowserManager() as bm:
            assert bm.browser is not None
            result = await render(bm.browser, "about:blank", timeout=5)
            assert result is not None
        return True, "ok"
    except Exception as e:
        msg = str(e).splitlines()[0] if str(e) else type(e).__name__
        return False, msg
