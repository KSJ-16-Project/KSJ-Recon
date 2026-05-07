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


# ── 파라미터 컨텍스트 판정 / 페이로드 변환 ─────────────────────

def _to_integer_context(payload: str) -> str:
    """문자열 컨텍스트 페이로드(`' AND ...`)를 정수 컨텍스트(` AND ...`)로 변환한다.
    선행 단따옴표를 제거해 정수 비교문 뒤에 자연스럽게 이어지도록 한다.
    """
    if payload.startswith("' "):
        return payload[1:]
    if payload.startswith("'"):
        return " " + payload[1:].lstrip()
    return payload


# ── 파라미터 주입 ───────────────────────────────────────────────

def _build_baseline_request(url: str, params: list[Parameter]) -> tuple[str, dict]:
    """모든 파라미터 원본 값으로 baseline URL과 body를 구성한다."""
    current_url = url
    body: dict[str, str] = {}
    for param in params:
        if param.location == ParamLocation.QUERY:
            parsed = urlparse(current_url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param.name] = [param.value]
            current_url = urlunparse(parsed._replace(query=urlencode({k: v[0] for k, v in qs.items()})))
        elif param.location == ParamLocation.BODY:
            body[param.name] = param.value
    return current_url, body


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
    # COOKIE 파라미터는 _build_headers가 Cookie 헤더를 완전히 구성하므로
    # cookies= 파라미터에 중복으로 넘기지 않는다
    cookies = {} if param.location == ParamLocation.COOKIE else _build_cookies(auth)

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

        # 인증 만료 감지: auth가 제공된 상태에서 401/403이면 세션 만료로 간주.
        # auth가 비어있으면 만료 개념 없음 (공개 페이지)
        auth_expired = bool(auth) and resp.status_code in (401, 403)

        return ProbeLog(
            param=param.name,
            payload=payload,
            response_status=resp.status_code,
            response_length=len(resp.content),
            matched_pattern=matched,
            elapsed_ms=round(elapsed_ms, 2),
            auth_expired=auth_expired,
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
    """파라미터 × 페이로드 전체 조합을 동시에 전송한다."""
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=True) as client:
        csrf_tokens: dict[str, str] = {}

        # POST 전 현재 세션으로 페이지를 GET해 최신 CSRF 토큰을 취득한다.
        # CSRF 토큰은 요청마다 회전할 수 있으므로 login 모듈이 아닌 여기서 직접 취득한다.
        if method == "POST" or any(p.location == ParamLocation.BODY for p in params):
            csrf_tokens = await fetch_csrf_token(client, url, auth)

        tasks = [
            send_probe(client, url, param, payload, auth, method, csrf_tokens or None)
            for param in params
            for payload in payloads
        ]
        return await asyncio.gather(*tasks)
