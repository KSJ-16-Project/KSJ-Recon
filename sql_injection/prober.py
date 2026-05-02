import asyncio
import re
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx

from .models import Parameter, ParamLocation, ProbeLog
from .payloads import ERROR_PATTERNS


DEFAULT_TIMEOUT = 10.0
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}

# 자동 탐지할 CSRF 토큰 필드명 목록
CSRF_FIELD_NAMES = [
    "csrf_token",
    "_token",
    "csrfmiddlewaretoken",   # Django
    "authenticity_token",    # Rails
    "__RequestVerificationToken",  # ASP.NET
    "csrf",
    "_csrf",
    "xsrf_token",
]


# ── CSRF 토큰 추출 ──────────────────────────────────────────────

async def fetch_csrf_token(
    client: httpx.AsyncClient,
    url: str,
    auth: dict[str, str],
) -> dict[str, str]:
    """
    GET 요청으로 페이지를 받아 CSRF 토큰을 추출한다.
    hidden input과 meta 태그 두 곳을 탐색하며,
    발견된 토큰을 {필드명: 값} dict로 반환한다.
    """
    headers = {**DEFAULT_HEADERS}
    for k, v in auth.items():
        if k.lower() != "cookie":
            headers[k] = v

    cookies = _build_cookies(auth)

    try:
        resp = await client.get(url, headers=headers, cookies=cookies)
    except httpx.RequestError:
        return {}

    tokens: dict[str, str] = {}
    body = resp.text

    # <input type="hidden" name="csrf_token" value="..."> 패턴
    for name in CSRF_FIELD_NAMES:
        pattern = rf'<input[^>]+name=["\']({re.escape(name)})["\'][^>]+value=["\']([^"\']+)["\']'
        match = re.search(pattern, body, re.IGNORECASE)
        if not match:
            # name/value 순서가 반대인 경우
            pattern = rf'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']({re.escape(name)})["\']'
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                tokens[name] = match.group(1)
        else:
            tokens[match.group(1)] = match.group(2)

    # <meta name="csrf-token" content="..."> 패턴
    meta_match = re.search(
        r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
        body, re.IGNORECASE
    )
    if meta_match:
        tokens["csrf-token"] = meta_match.group(1)

    return tokens


# ── 파라미터 주입 ───────────────────────────────────────────────

def _inject_param(url: str, param: Parameter, payload: str) -> tuple[str, dict]:
    """
    파라미터 위치에 따라 페이로드를 주입한 (url, body) 튜플을 반환한다.
    기존 값 뒤에 페이로드를 붙여 앱이 정상 파싱 후 SQL 처리까지 도달하게 한다.
    """
    injected_value = param.value + payload

    if param.location == ParamLocation.QUERY:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param.name] = [injected_value]
        new_query = urlencode({k: v[0] for k, v in qs.items()})
        new_url = urlunparse(parsed._replace(query=new_query))
        return new_url, {}

    if param.location == ParamLocation.BODY:
        return url, {param.name: injected_value}

    return url, {}


# ── 헤더 / 쿠키 구성 ────────────────────────────────────────────

def _build_headers(param: Parameter, payload: str, auth: dict[str, str]) -> dict:
    headers = {**DEFAULT_HEADERS}

    for k, v in auth.items():
        if k.lower() != "cookie":
            headers[k] = v

    if param.location == ParamLocation.HEADER:
        headers[param.name] = payload
    elif param.location == ParamLocation.COOKIE:
        cookie_str = auth.get("cookie", "")
        extra = f"{param.name}={payload}"
        headers["Cookie"] = f"{cookie_str}; {extra}".strip("; ")

    return headers


def _build_cookies(auth: dict[str, str]) -> dict:
    """auth["cookie"] 문자열을 httpx cookies 인자용 dict로 변환한다."""
    raw = auth.get("cookie", "")
    cookies = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


# ── 응답 분석 ───────────────────────────────────────────────────

def match_error_pattern(body: str) -> str | None:
    """응답 body에서 SQL 에러 패턴을 탐색한다. 첫 번째 매칭 패턴을 반환."""
    lower = body.lower()
    for pattern, _ in ERROR_PATTERNS:
        if pattern in lower:
            return pattern
    return None


# ── 단일 요청 ───────────────────────────────────────────────────

async def send_probe(
    client: httpx.AsyncClient,
    url: str,
    param: Parameter,
    payload: str,
    auth: dict[str, str],
    method: str = "GET",
    csrf_tokens: dict[str, str] | None = None,
) -> ProbeLog:
    injected_url, body = _inject_param(url, param, payload)
    headers = _build_headers(param, payload, auth)
    cookies = _build_cookies(auth) 

    # CSRF 토큰을 POST body에 추가
    if csrf_tokens:
        body.update(csrf_tokens)

    start = time.monotonic()
    try:
        if method == "POST" or param.location == ParamLocation.BODY:
            resp = await client.post(injected_url, data=body, headers=headers, cookies=cookies)
        else:
            resp = await client.get(injected_url, headers=headers, cookies=cookies)

        elapsed_ms = (time.monotonic() - start) * 1000
        matched = match_error_pattern(resp.text)

        return ProbeLog(
            param=param.name,
            payload=payload,
            response_status=resp.status_code,
            response_length=len(resp.content),
            matched_pattern=matched,
            elapsed_ms=round(elapsed_ms, 2),
        )
    except httpx.RequestError:
        elapsed_ms = (time.monotonic() - start) * 1000
        return ProbeLog(
            param=param.name,
            payload=payload,
            response_status=0,
            response_length=0,
            elapsed_ms=round(elapsed_ms, 2),
        )


# ── 동시 요청 ───────────────────────────────────────────────────

async def send_probes_concurrent(
    url: str,
    params: list[Parameter],
    payloads: list[str],
    auth: dict[str, str],
    method: str = "GET",
) -> list[ProbeLog]:
    """
    파라미터 × 페이로드 전체 조합을 동시에 전송한다.

    CSRF 토큰 계약:
      - Login 모듈이 로그인 완료 후 auth["csrf_token"]에 토큰을 채워서 전달한다.
      - 이 모듈은 auth에서 꺼내 쓰기만 하며, 직접 취득하지 않는다.
      - 토큰 만료 시 auth_expired 감지 → 오케스트레이터 → Login 모듈 재호출 경로로 처리한다.

    TODO: Login 모듈 미구현 상태. 구현 완료 후 아래 주석을 제거하고 auth 기반으로 전환할 것.
    """
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=True) as client:
        csrf_tokens: dict[str, str] = {}

        # [TEMP] Login 모듈 구현 전 임시: 페이지에서 직접 CSRF 토큰을 추출한다.
        # Login 모듈 완성 후 아래 블록을 제거하고 auth["csrf_token"] 방식으로 교체할 것.
        if method == "POST" or any(p.location == ParamLocation.BODY for p in params):
            csrf_tokens = await fetch_csrf_token(client, url, auth)

        # [FUTURE] Login 모듈 완성 후 위 블록 대신 아래 코드를 사용한다.
        # if "csrf_token" in auth:
        #     csrf_tokens = {"csrf_token": auth["csrf_token"]}

        tasks = [
            send_probe(client, url, param, payload, auth, method, csrf_tokens or None)
            for param in params
            for payload in payloads
        ]
        return await asyncio.gather(*tasks)
