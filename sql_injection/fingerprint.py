import asyncio
from dataclasses import dataclass

import httpx

from .models import DBMSType, Confidence, Parameter, ProbeLog, NmapDBInfo
from .payloads import (
    NMAP_PORT_MAP,
    NMAP_SERVICE_MAP,
    ERROR_PROBES,
    ERROR_PATTERNS,
    BOOLEAN_PROBES,
)
from .prober import send_probes_concurrent, send_probe


@dataclass
class DBMSDetectResult:
    dbms: DBMSType
    confidence: Confidence
    injectable_params: list[str]
    probe_log: list[ProbeLog]


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
) -> tuple[DBMSType, list[str], list[ProbeLog]]:
    logs = await send_probes_concurrent(url, params, ERROR_PROBES, auth, method)
    dbms, injectable = _parse_dbms_from_logs(logs)
    return dbms, injectable, logs


# ── Phase 2: Boolean-based DBMS 식별 ──────────────────────────

async def detect_by_boolean(
    url: str,
    params: list[Parameter],
    auth: dict[str, str],
    method: str = "GET",
) -> tuple[DBMSType, list[str], list[ProbeLog]]:
    all_logs: list[ProbeLog] = []
    injectable: set[str] = set()
    dbms_scores: dict[DBMSType, int] = {}

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        for param in params:
            for dbms, true_payload, false_payload in BOOLEAN_PROBES:
                true_log, false_log = await asyncio.gather(
                    send_probe(client, url, param, true_payload, auth, method),
                    send_probe(client, url, param, false_payload, auth, method),
                )
                all_logs.extend([true_log, false_log])

                length_diff = abs(true_log.response_length - false_log.response_length)
                status_diff = true_log.response_status != false_log.response_status

                if length_diff > 50 or status_diff:
                    dbms_scores[dbms] = dbms_scores.get(dbms, 0) + 1
                    injectable.add(param.name)

    if not dbms_scores:
        return DBMSType.UNKNOWN, [], all_logs

    best = max(dbms_scores, key=lambda d: dbms_scores[d])
    return best, list(injectable), all_logs


# ── 통합 진입점 ────────────────────────────────────────────────

async def detect_dbms(
    url: str,
    params: list[Parameter],
    auth: dict[str, str],
    nmap_data: NmapDBInfo | None = None,
    method: str = "GET",
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
        )

    # Phase 1
    dbms, injectable, logs = await detect_by_error(url, params, auth, method)
    all_logs.extend(logs)
    if dbms != DBMSType.UNKNOWN:
        return DBMSDetectResult(
            dbms=dbms,
            confidence=Confidence.HIGH,
            injectable_params=injectable,
            probe_log=all_logs,
        )

    # Phase 2
    dbms, injectable, logs = await detect_by_boolean(url, params, auth, method)
    all_logs.extend(logs)
    if dbms != DBMSType.UNKNOWN:
        return DBMSDetectResult(
            dbms=dbms,
            confidence=Confidence.MEDIUM,
            injectable_params=injectable,
            probe_log=all_logs,
        )

    return DBMSDetectResult(
        dbms=DBMSType.UNKNOWN,
        confidence=Confidence.LOW,
        injectable_params=[],
        probe_log=all_logs,
    )
