import asyncio

from .models import (
    ScanInput, ScanOutput, TechniqueQueries,
    ProbeLog, ParamLocation, DBMSType, Confidence,
)
from .fingerprint import detect_dbms, DBMSDetectResult
from .version import extract_version
from .payloads import POSSIBLE_QUERIES, BOOLEAN_PROBES, ERROR_PROBES


# ── 기법 선별 ───────────────────────────────────────────────────

def _select_techniques(
    dbms: DBMSType,
    detect_result: DBMSDetectResult,
    all_logs: list[ProbeLog],
    scan_input: ScanInput,
) -> TechniqueQueries:
    confirmed: dict[str, list[str]] = {}
    possible: dict[str, list[str]] = {}
    dbms_queries = POSSIBLE_QUERIES.get(dbms, {})

    # confirmed: Phase 1 ERROR_PROBES 중 실제 에러 패턴이 매칭된 페이로드만
    # (버전 프로브 등 다른 Phase 페이로드가 우연히 에러를 내도 포함하지 않음)
    error_payloads = [log.payload for log in all_logs if log.matched_pattern and log.payload in ERROR_PROBES]
    if error_payloads:
        confirmed["Error-based"] = error_payloads

    # confirmed: Phase 2 Boolean 차이가 확인된 경우
    # 실제 매칭에 사용된 BOOLEAN_PROBES 페이로드만 기록 (canned 쿼리 X)
    if detect_result.confidence == Confidence.MEDIUM:
        for probe_dbms, true_p, false_p in BOOLEAN_PROBES:
            if probe_dbms == dbms:
                confirmed["Boolean-based blind"] = [true_p, false_p]
                break

    # possible: Union-based (주입 포인트 확인된 경우)
    if detect_result.injectable_params:
        possible["Union-based"] = dbms_queries.get("Union-based", [])

    # possible: Time-based (응답 시간 1초 이상 차이 감지)
    if any(log.elapsed_ms and log.elapsed_ms > 1000 for log in all_logs):
        possible["Time-based blind"] = dbms_queries.get("Time-based blind", [])

    # possible: Stacked queries (POST/BODY 파라미터 있는 경우)
    if any(p.location == ParamLocation.BODY for p in scan_input.crawler_data):
        possible["Stacked queries"] = dbms_queries.get("Stacked queries", [])

    # possible: Nmap이 DB 포트 직접 발견 → 더 열린 환경
    if scan_input.nmap_data:
        if dbms == DBMSType.MYSQL:
            possible["File read/write"] = dbms_queries.get("File read/write", [])
        elif dbms == DBMSType.MSSQL:
            possible["xp_cmdshell"] = dbms_queries.get("xp_cmdshell", [])
        elif dbms == DBMSType.POSTGRESQL:
            possible["File access"] = dbms_queries.get("File access", [])

    # 항상 포함: Info gathering
    if dbms != DBMSType.UNKNOWN:
        possible["Info gathering"] = dbms_queries.get("Info gathering", [])

    return TechniqueQueries(confirmed=confirmed, possible=possible)


# ── 세션 만료 감지 ──────────────────────────────────────────────

def _check_auth_expired(all_logs: list[ProbeLog]) -> bool:
    """probe_log 중 하나라도 auth_expired면 True 반환."""
    return any(log.auth_expired for log in all_logs)


# ── 메인 오케스트레이션 ─────────────────────────────────────────

async def run_scan(scan_input: ScanInput) -> ScanOutput:
    auth = scan_input.auth
    all_logs: list[ProbeLog] = []

    # 빈 params 가드
    if not scan_input.crawler_data:
        return ScanOutput(
            dbms_type=DBMSType.UNKNOWN,
            dbms_version=None,
            confidence=Confidence.LOW,
            injectable_params=[],
            technique_queries=TechniqueQueries(confirmed={}, possible={}),
            probe_log=[],
            auth_expired=False,
        )

    try:
        # 프로빙할 URL 목록: target_url + fuzzer_data
        target_urls = [scan_input.target_url] + scan_input.fuzzer_data
        best_result: DBMSDetectResult | None = None

        # DBMS 탐지 — 첫 번째로 UNKNOWN 아닌 결과 채택
        for url in target_urls:
            result = await detect_dbms(
                url=url,
                params=scan_input.crawler_data,
                auth=auth,
                nmap_data=scan_input.nmap_data,
            )
            all_logs.extend(result.probe_log)

            if best_result is None:
                best_result = result
            if result.dbms != DBMSType.UNKNOWN:
                best_result = result
                break

        # 세션 만료 감지 → 즉시 반환 (오케스트레이터가 Login 모듈 재호출)
        if _check_auth_expired(all_logs):
            return ScanOutput(
                dbms_type=DBMSType.UNKNOWN,
                dbms_version=None,
                confidence=Confidence.LOW,
                injectable_params=[],
                technique_queries=TechniqueQueries(confirmed={}, possible={}),
                probe_log=all_logs,
                auth_expired=True,
            )

        # 버전 추출 — DBMS가 실제로 식별된 URL을 사용해야 함
        # (메인 타겟이 막혀 있고 fuzzer URL에서 식별된 경우, 메인으로 가면 항상 실패)
        injectable_names = set(best_result.injectable_params)
        injectable_params = [p for p in scan_input.crawler_data if p.name in injectable_names]
        version, version_logs = await extract_version(
            dbms=best_result.dbms,
            url=best_result.url or scan_input.target_url,
            params=injectable_params or scan_input.crawler_data,
            auth=auth,
            nmap_data=scan_input.nmap_data,
        )
        all_logs.extend(version_logs)

        # 기법 선별
        techniques = _select_techniques(
            dbms=best_result.dbms,
            detect_result=best_result,
            all_logs=all_logs,
            scan_input=scan_input,
        )

        return ScanOutput(
            dbms_type=best_result.dbms,
            dbms_version=version,
            confidence=best_result.confidence,
            injectable_params=best_result.injectable_params,
            technique_queries=techniques,
            probe_log=all_logs,
            auth_expired=False,
        )

    except asyncio.CancelledError:
        return ScanOutput(
            dbms_type=DBMSType.UNKNOWN,
            dbms_version=None,
            confidence=Confidence.LOW,
            injectable_params=[],
            technique_queries=TechniqueQueries(confirmed={}, possible={}),
            probe_log=all_logs,
            auth_expired=False,
        )
