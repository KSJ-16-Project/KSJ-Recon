import asyncio
from dataclasses import dataclass

import httpx

from .models import DBMSType, Confidence, Parameter, ParamLocation, ProbeLog, NmapDBInfo
from .payloads import (
    NMAP_PORT_MAP,
    NMAP_SERVICE_MAP,
    ERROR_PROBES,
    ERROR_PATTERNS,
    BOOLEAN_PROBES,
)
from .prober import (
    send_probes_concurrent, send_probe,
    _to_integer_context,
    fetch_csrf_token,
)


@dataclass
class DBMSDetectResult:
    dbms: DBMSType
    confidence: Confidence
    injectable_params: list[str]
    probe_log: list[ProbeLog]
    url: str = ""   # DBMS가 식별된 URL (Phase 3 버전 추출이 같은 URL을 사용하도록)


# ── Phase 0: Nmap 데이터로 즉시 확정 ───────────────────────────

def detect_from_nmap(nmap_data: NmapDBInfo | None) -> DBMSType | None:
    if nmap_data is None:
        return None

    if nmap_data.port in NMAP_PORT_MAP:
        return NMAP_PORT_MAP[nmap_data.port]

    service = nmap_data.service.lower()
    for key, dbms in NMAP_SERVICE_MAP.items():
        if key in service:
            return dbms

    if nmap_data.version:
        version_lower = nmap_data.version.lower()
        keywords = {
            "mysql":         DBMSType.MYSQL,
            "postgresql":    DBMSType.POSTGRESQL,
            "postgres":      DBMSType.POSTGRESQL,
            "microsoft sql": DBMSType.MSSQL,
            "oracle":        DBMSType.ORACLE,
            "sqlite":        DBMSType.SQLITE,
        }
        for kw, dbms in keywords.items():
            if kw in version_lower:
                return dbms

    return None


# ── Phase 1: 에러 메시지 패턴으로 DBMS 확정 ───────────────────

def _parse_dbms_from_logs(logs: list[ProbeLog]) -> tuple[DBMSType, list[str]]:
    matched_dbms: dict[DBMSType, int] = {}
    injectable: set[str] = set()

    for log in logs:
        if log.matched_pattern is None:
            continue
        pattern_lower = log.matched_pattern.lower()
        for pattern, dbms in ERROR_PATTERNS:
            if pattern == pattern_lower:
                matched_dbms[dbms] = matched_dbms.get(dbms, 0) + 1
                injectable.add(log.param)
                break

    if not matched_dbms:
        return DBMSType.UNKNOWN, []

    best = max(matched_dbms, key=lambda d: matched_dbms[d])
    return best, list(injectable)


async def detect_by_error(
    url: str,
    params: list[Parameter],
    auth: dict[str, str],
    method: str = "GET",
    enctype: str = "",
) -> tuple[DBMSType, list[str], list[ProbeLog]]:
    logs = await send_probes_concurrent(url, params, ERROR_PROBES, auth, method, enctype)
    dbms, injectable = _parse_dbms_from_logs(logs)
    return dbms, injectable, logs


# ── Phase 2: Boolean-based DBMS 식별 ──────────────────────────

async def _run_boolean_phase(
    url: str,
    params: list[Parameter],
    auth: dict[str, str],
    method: str,
    transform,
    enctype: str = "",
) -> tuple[DBMSType, list[str], list[ProbeLog]]:
    """주어진 페이로드 변환 함수로 Phase 2를 수행한다.
    transform=None이면 string context, _to_integer_context면 integer context.
    """
    all_logs: list[ProbeLog] = []
    injectable: set[str] = set()
    dbms_scores: dict[DBMSType, int] = {}

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        # POST/BODY 조건이면 CSRF 토큰 1회 취득 (phase 마다 새 client라 Phase 1 토큰 재사용 불가)
        csrf_tokens: dict[str, str] = {}
        if method == "POST" or any(p.location == ParamLocation.BODY for p in params):
            csrf_tokens = await fetch_csrf_token(client, url, auth)

        for param in params:
            for dbms, true_payload, false_payload in BOOLEAN_PROBES:
                tp = transform(true_payload) if transform else true_payload
                fp = transform(false_payload) if transform else false_payload
                true_log, false_log = await asyncio.gather(
                    send_probe(client, url, param, tp, auth, method,
                               csrf_tokens=csrf_tokens or None, enctype=enctype, all_params=params),
                    send_probe(client, url, param, fp, auth, method,
                               csrf_tokens=csrf_tokens or None, enctype=enctype, all_params=params),
                )
                all_logs.extend([true_log, false_log])

                length_diff = abs(true_log.response_length - false_log.response_length)
                status_diff = true_log.response_status != false_log.response_status
                threshold = max(50, int(max(true_log.response_length, false_log.response_length) * 0.01))

                if length_diff > threshold or status_diff:
                    dbms_scores[dbms] = dbms_scores.get(dbms, 0) + 1
                    injectable.add(param.name)

    if not dbms_scores:
        return DBMSType.UNKNOWN, [], all_logs

    best = max(dbms_scores, key=lambda d: dbms_scores[d])
    return best, list(injectable), all_logs


async def detect_by_boolean(
    url: str,
    params: list[Parameter],
    auth: dict[str, str],
    method: str = "GET",
    enctype: str = "",
) -> tuple[DBMSType, list[str], list[ProbeLog]]:
    """파라미터 컨텍스트(따옴표 wrapping 여부)를 외부에서 알 수 없으므로,
    string context로 먼저 시도하고 식별 실패 시 integer context로 재시도한다.
    """
    # 1차: string context
    dbms, injectable, logs = await _run_boolean_phase(
        url, params, auth, method, transform=None, enctype=enctype
    )
    if dbms != DBMSType.UNKNOWN:
        return dbms, injectable, logs

    # 2차: integer context fallback
    dbms2, injectable2, logs2 = await _run_boolean_phase(
        url, params, auth, method, transform=_to_integer_context, enctype=enctype
    )
    return dbms2, injectable2, logs + logs2


# ── 통합 진입점 ────────────────────────────────────────────────

async def detect_dbms(
    url: str,
    params: list[Parameter],
    auth: dict[str, str],
    nmap_data: NmapDBInfo | None = None,
    method: str = "GET",
    enctype: str = "",
) -> DBMSDetectResult:
    all_logs: list[ProbeLog] = []

    # Phase 0
    dbms = detect_from_nmap(nmap_data)
    if dbms:
        return DBMSDetectResult(
            dbms=dbms,
            confidence=Confidence.HIGH,
            injectable_params=[],
            probe_log=[],
            url=url,
        )

    # Phase 1
    dbms, injectable, logs = await detect_by_error(url, params, auth, method, enctype)
    all_logs.extend(logs)
    if dbms != DBMSType.UNKNOWN:
        return DBMSDetectResult(
            dbms=dbms,
            confidence=Confidence.HIGH,
            injectable_params=injectable,
            probe_log=all_logs,
            url=url,
        )

    # Phase 2
    dbms, injectable, logs = await detect_by_boolean(url, params, auth, method, enctype)
    all_logs.extend(logs)
    if dbms != DBMSType.UNKNOWN:
        return DBMSDetectResult(
            dbms=dbms,
            confidence=Confidence.MEDIUM,
            injectable_params=injectable,
            probe_log=all_logs,
            url=url,
        )

    return DBMSDetectResult(
        dbms=DBMSType.UNKNOWN,
        confidence=Confidence.LOW,
        injectable_params=[],
        probe_log=all_logs,
        url=url,
    )
