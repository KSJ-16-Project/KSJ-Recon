from dataclasses import dataclass, field
from typing import Optional

from playwright.async_api import Browser, BrowserContext, Playwright, async_playwright


_LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--mute-audio",
]


@dataclass
class XHRRecord:
    url: str = ""
    method: str = "GET"
    resource_type: str = ""
    post_data: str = ""
    status_code: int = 0
    response_headers: dict = field(default_factory=dict)
    body_preview: str = ""
    mime: str = ""
    params: dict = field(default_factory=dict)


@dataclass
class WSRecord:
    url: str = ""
    sent_preview: str = ""
    received_preview: str = ""
    closed: bool = False
    close_code: int = 0


@dataclass
class RawPageData:
    url: str = ""
    status: int = 0
    request_headers: dict = field(default_factory=dict)
    response_headers: dict = field(default_factory=dict)
    raw_html: str = ""
    rendered_html: str = ""
    xhr_list: list = field(default_factory=list)
    ws_list: list = field(default_factory=list)
    cookies: list = field(default_factory=list)
    discovered_urls: list = field(default_factory=list)
    download_urls: list = field(default_factory=list)


class BrowserManager:
    """Playwright Chromium 브라우저 생성/해제 async context manager."""

    def __init__(
        self,
        headless: bool = False,
        cookies: Optional[list] = None,
    ):
        self.headless = headless
        self._initial_cookies: list = cookies or []
        self._pw: Optional[Playwright] = None
        self.browser: Optional[Browser] = None

    async def __aenter__(self) -> "BrowserManager":
        self._pw = await async_playwright().start()
        self.browser = await self._pw.chromium.launch(
            headless=self.headless,
            args=_LAUNCH_ARGS,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        try:
            if self.browser is not None:
                await self.browser.close()
        finally:
            if self._pw is not None:
                await self._pw.stop()
            self.browser = None
            self._pw = None

    async def close(self) -> None:
        await self.__aexit__(None, None, None)

    async def new_context(self, **kwargs) -> BrowserContext:
        assert self.browser is not None
        ctx = await self.browser.new_context(**kwargs)
        if self._initial_cookies:
            await ctx.add_cookies(self._initial_cookies)
        return ctx
