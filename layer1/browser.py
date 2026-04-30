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
# XHR/fetch 요청 하나의 정보 (url, method, body, 응답 status 등)
# XHR/fetch == 새로고침 X, 뒤에서 서버와 데이터 주고 받는 통신
class XHRRecord:
    url: str = ""
    method: str = "GET" #디폴트 설정, 덮어씌워짐
    resource_type: str = "" 
    post_data: str = "" #Request 패킷 Body 값 가져옴
    status_code: int = 0 #지금은 NULL이지만, 응답 받으면 채워짐
    response_headers: dict = field(default_factory=dict) # 응답 받은 헤더를 딕셔너리 구조로 저장
    body_preview: str = "" #Response 패킷 Body 값 가져옴. 4KB만 받고, 뒤에 버림. 미리보기 용도
    mime: str = "" #페이지가 보내는 데이터 형식을 저장. text/html, application/json, image/png 등

#코드 이해 및 검증 완료

@dataclass
# WebSocket 연결 하나의 DATA 클래스
# ws:// 혹은 wss://로 시작

class WSRecord:
    url: str = ""
    sent_preview: str = "" #송신 프레임으로 서버에게 어떤 형식으로 요청해야 하는지 알 수 있음
    received_preview: str = ""
    closed: bool = False
    close_code: int = 0 # 문제 없이 잘 닫혔으면 1000이 1006이면 비정상 종료임? 그럼 다른 것들은? 뭐있음?


@dataclass
# render.py가 최종적으로 반환하는 raw 데이터 묶음
# WebSocket 연결 하나의 정보 (url, 송수신 프레임 미리보기)
# render.py가 최종적으로 반환하는 한 개의 페이지의 모든 raw 데이터.
# raw 데이터 == 
class RawPageData:
    url: str = ""
    status: int = 0
    request_headers: dict = field(default_factory=dict)
    response_headers: dict = field(default_factory=dict)
    raw_html: str = ""
    rendered_html: str = ""
    xhr_list: list = field(default_factory=list)   # list[XHRRecord]
    ws_list: list = field(default_factory=list)    # list[WSRecord]
    cookies: list = field(default_factory=list)    # list[str]


class BrowserManager:
    """Playwright Chromium 브라우저 생성/해제 async context manager."""

    def __init__(
        self,
        #제대로 동작하는지 검증하기 위해 headless 모드 끔. 필요하면 True로 바꿔서 실행해보기
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
        """새 브라우저 컨텍스트를 생성하고 초기 쿠키를 주입한다."""
        assert self.browser is not None
        ctx = await self.browser.new_context(**kwargs)
        if self._initial_cookies:
            await ctx.add_cookies(self._initial_cookies)
        return ctx
        
