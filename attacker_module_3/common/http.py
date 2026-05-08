"""스레드-안전 HTTP 클라이언트 래퍼."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# 응답 본문 64KiB 상한 — 메모리 보호용
_BODY_CAP = 65_536


@dataclass
#HTTP 응답 결과를 담는 공통 클래스
class HttpResponse:
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed_ms: float = 0.0
    truncated: bool = False # 응답이 _BODY_CAP 보다 커서 잘렸는지 여부
    # 전송 실패 시 메시지, 정상 응답이면 None
    error: str | None = None

    #요청 중 오류 여부
    @property
    def ok(self) -> bool:
        return self.error is None

#HTTP 클라이언트의 기본 설정 
class HttpClient:
    def __init__(
        self,
        *,
        timeout: float = 10.0,
        verify: bool = True,
        proxies: dict[str, str] | None = None,
        user_agent: str = "DAST-Attacker/0.1",
        max_retries: int = 0, #실패 시 재시도 횟수
        pool_size: int = 20, #연결 풀 크기
        allow_redirects: bool = False,
        scope_predicate: Callable[[str], bool] | None = None, #요청 URL이 허용 범위인지 검사
    ) -> None:
        self.timeout = timeout
        self.allow_redirects = allow_redirects
        self.scope_predicate = scope_predicate


        #requests.Session 을 사용하여 연결 풀과 재시도 정책을 설정한다
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.session.verify = verify
        if proxies:
            self.session.proxies.update(proxies)

        retry = Retry(
            total=max_retries,
            backoff_factor=0.2,
            allowed_methods=frozenset({"GET", "POST"}),
        )
        adapter = HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size,
            max_retries=retry,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    #실제 HTTP 요청을 보내는 메서드
    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        # 스코프 가드 — 부모 DAST 가 허용된 URL만 검사하도록 지정 가능
        if self.scope_predicate is not None and not self.scope_predicate(url):
            return HttpResponse(error="out-of-scope")

        start = time.perf_counter()
        try:
            r = self.session.request(
                method.upper(),
                url,
                params=params,
                data=data,
                headers=headers,
                timeout=timeout if timeout is not None else self.timeout,
                allow_redirects=self.allow_redirects,
                stream=True,
            )
            # 본문은 항상 64KiB 까지만 읽어들인다 — 응답이 거대해도 안전하게 차단
            body = b""
            truncated = False
            try:
                for chunk in r.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    if len(body) + len(chunk) > _BODY_CAP:
                        body += chunk[: _BODY_CAP - len(body)]
                        truncated = True
                        break
                    body += chunk
            finally:
                r.close()

            elapsed = (time.perf_counter() - start) * 1000.0
            return HttpResponse(
                status_code=r.status_code,
                headers=dict(r.headers),
                body=body,
                elapsed_ms=elapsed,
                truncated=truncated,
            )
        #requests 계열 오류 처리
        except requests.RequestException as exc:
            elapsed = (time.perf_counter() - start) * 1000.0
            return HttpResponse(error=str(exc), elapsed_ms=elapsed)
