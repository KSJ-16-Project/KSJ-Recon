import asyncio

import ksj_login

from .models import (
    ScanInput, ScanOutput, TechniqueQueries,
    ProbeLog, ParamLocation, DBMSType, Confidence,
    Endpoint,
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
    error_payloads = list(dict.fromkeys(
        log.payload for log in all_logs if log.matched_pattern and log.payload in ERROR_PROBES
    ))
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

    # possible: Stacked queries (어떤 endpoint든 BODY 파라미터가 있으면)
    has_body = any(
        p.location == ParamLocation.BODY
        for ep in scan_input.endpoints
        for p in ep.params
    )
    if has_body:
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


# ── 직접 재로그인 ───────────────────────────────────────────────

async def _try_relogin() -> dict[str, str] | None:
    """ksj_login 모듈에서 직접 새 세션을 받아온다.

    Core가 사전에 store_credentials()를 호출해두면 이 함수가
    호출될 때 has_credentials()가 True가 되어 직접 재로그인이 가능하다.
    실패 시 None 반환.
    """
    if not ksj_login.has_credentials():
        return None
    auth_result = await ksj_login.get_session()
    if not auth_result.success:
        return None
    return {"cookie": ksj_login.to_cookie_header(auth_result.cookies)}


def _empty_output(
    probe_log: list[ProbeLog] | None = None,
    auth_expired: bool = False,
) -> ScanOutput:
    return ScanOutput(
        dbms_type=DBMSType.UNKNOWN,
        dbms_version=None,
        confidence=Confidence.LOW,
        injectable_params=[],
        technique_queries=TechniqueQueries(confirmed={}, possible={}),
        probe_log=probe_log or [],
        auth_expired=auth_expired,
    )


# ── 메인 오케스트레이션 ─────────────────────────────────────────

async def run_scan(scan_input: ScanInput) -> ScanOutput:
    auth = scan_input.auth
    all_logs: list[ProbeLog] = []

    # 빈 endpoints 가드
    if not scan_input.endpoints:
        return _empty_output()

    try:
        best_result: DBMSDetectResult | None = None
        best_endpoint: Endpoint | None = None
        # (param, url, method) 트리플 → 출력 dict. 같은 트리플의 다른 value들은 values 배열에 누적
        injectable_map: dict[tuple, dict] = {}
        failed: set[tuple] = set()             # 재시도 후에도 실패한 (url, method)
        relogin_unavailable = False            # 한 번이라도 재로그인 불가 발생

        # endpoint 단위 순회 — DBMS 확정 후에도 injectable params 계속 수집
        for ep in scan_input.endpoints:
            key = (ep.url, ep.method)
            if key in failed:
                continue
            if not ep.params:
                continue

            result = await detect_dbms(
                url=ep.url,
                params=ep.params,
                auth=auth,
                nmap_data=scan_input.nmap_data,
                method=ep.method,
                enctype=ep.enctype,
            )
            all_logs.extend(result.probe_log)

            if _check_auth_expired(result.probe_log):
                new_auth = await _try_relogin()
                if new_auth:
                    auth = new_auth
                    # 같은 endpoint 재시도
                    result = await detect_dbms(
                        url=ep.url,
                        params=ep.params,
                        auth=auth,
                        nmap_data=scan_input.nmap_data,
                        method=ep.method,
                        enctype=ep.enctype,
                    )
                    all_logs.extend(result.probe_log)
                    if _check_auth_expired(result.probe_log):
                        failed.add(key)
                        continue
                else:
                    # 재로그인 불가(자격증명 없음 또는 로그인 실패)
                    # → 해당 endpoint만 스킵, 공개 endpoint는 계속 시도
                    failed.add(key)
                    relogin_unavailable = True
                    continue

            for param_name in result.injectable_params:
                triple = (param_name, ep.url, ep.method)
                value = next((p.value for p in ep.params if p.name == param_name), "")
                entry = injectable_map.get(triple)
                if entry is None:
                    injectable_map[triple] = {
                        "param": param_name,
                        "values": [value],
                        "url": ep.url,
                        "method": ep.method,
                    }
                elif value not in entry["values"]:
                    entry["values"].append(value)

            if best_result is None:
                best_result = result
                best_endpoint = ep
            if result.dbms != DBMSType.UNKNOWN:
                best_result = result
                best_endpoint = ep

        # 모든 endpoint가 막힌 경우
        if best_result is None or best_endpoint is None:
            return _empty_output(probe_log=all_logs, auth_expired=relogin_unavailable)

        # 버전 추출 — DBMS가 식별된 endpoint를 그대로 사용
        # (URL/method/enctype/폼 묶음을 그대로 쓰지 않으면 Phase 3가 항상 실패)
        all_injectable = list(injectable_map.values())
        injectable_names = {
            item["param"] for item in all_injectable
            if item["url"] == best_endpoint.url and item["method"] == best_endpoint.method
        }
        target_params = (
            [p for p in best_endpoint.params if p.name in injectable_names]
            or best_endpoint.params
        )
        version, version_logs = await extract_version(
            dbms=best_result.dbms,
            url=best_endpoint.url,
            params=target_params,
            auth=auth,
            nmap_data=scan_input.nmap_data,
            method=best_endpoint.method,
            enctype=best_endpoint.enctype,
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
            injectable_params=all_injectable,
            technique_queries=techniques,
            probe_log=all_logs,
            auth_expired=relogin_unavailable,
        )

    except asyncio.CancelledError:
        return _empty_output(probe_log=all_logs)
