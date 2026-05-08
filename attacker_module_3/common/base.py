"""모든 공격 모듈이 상속하는 공통 베이스 클래스."""
from __future__ import annotations

import asyncio
import os
import sys
import threading
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ClassVar, Iterable, Sequence

# ksj_login은 repo 루트의 형제 패키지 — 필요 시 경로 추가
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from attacker_module_3.common.detector import match
#HTTP 요청을 보내고 응답을 담는 공통 래퍼
from attacker_module_3.common.http import HttpClient, HttpResponse
from attacker_module_3.common.injector import inject
from attacker_module_3.common.exceptions import AuthenticationError
from attacker_module_3.common.io import dump_error, dump_report, load_request
from attacker_module_3.common.result import (
    Confidence,
    Finding,
    ScanReport,
    ScanStatus,
    Severity,
    confidence_rank,
    severity_rank,
)
from attacker_module_3.common.target import Target


async def _do_relogin_async() -> Any:
    """ksj_login.get_session()으로 재로그인 후 새 AuthResult 반환."""
    from ksj_login import get_session
    return await get_session()


_AUTH_REDIRECT_HINTS = ("login", "signin", "sign-in", "auth")


def _needs_reauth(resp: Any) -> bool:
    """401/403 또는 로그인 페이지로의 302 리다이렉트이면 재인증 필요로 판단한다."""
    if resp.status_code in (401, 403):
        return True
    if resp.status_code == 302:
        location = resp.headers.get("Location", "")
        return any(hint in location.lower() for hint in _AUTH_REDIRECT_HINTS)
    return False


#ScanReport를 위한 현재 시간 변환
def _now_iso() -> str:
    # 모든 시각은 UTC ISO-8601 (밀리초까지)
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"



@dataclass
#공격 모듈이 각 대상에 대해 시도할 검사 조합
class Probe:
    parameter: str
    payload_value: str
    category: str
    signatures: Sequence[bytes]
    confidence: Confidence
    severity_when_signed: Severity


#모든 공격 모듈의 부모 클래스
class AttackModule(ABC):
    # 공격 모듈의 식별을 위한 고유 이름
    name: ClassVar[str]

    #공격 모듈 객체를 위한 필수 공통 설정
    def __init__(
        self,
        *,
        http: HttpClient,
        max_workers: int = 8,
        #실행할 페이로드 개수 제한(None 이면 무제한)
        payload_limit: int | None = None,
    ) -> None:
        self.http = http
        self.max_workers = max(1, int(max_workers))
        self.payload_limit = payload_limit
        self._session_headers: dict[str, str] = {}  # target.headers 참조 — 재로그인 시 Cookie 덮어쓰기용
        self._relogin_lock = threading.Lock()
        self._session_version = 0

    # ---- 공개 API ---------------------------------------------------------

    # 공격 모듈 실행
    def run(self, target: Target) -> list[Finding]:
        """생성한 ScanReport에서 findings만 추출"""
        return list(self._run_with_report(target).findings)

    #부모 DAST 가 직접 호출하는 경로
    @classmethod
    async def run_json(cls, request: str | bytes | bytearray | dict[str, Any]) -> str:
        """JSON-in / JSON-out 진입점."""
        try:
            req = load_request(request) #JSON 요청을 프로젝트 내부에서 쓰기 좋은 형태로 파싱
        except (ValueError, TypeError):
            return dump_error("invalid_request", 0)

        try:
            http = HttpClient(**req.http_kwargs) #HTTP 클라이언트 생성
            module = cls(http=http, **req.module_kwargs) #공격 모듈 객체 생성
            report = module._run_with_report(req.target) #스캔 실행 후 JSON 반환
            return dump_report(report)
        except AuthenticationError as e:
            return dump_error("auth_required", e.status_code)
        except ImportError:
            return dump_error("ksj_login_unavailable", 0)

    # ---- 하위 클래스가 구현해야 하는 훅 ------------------------------------

    @abstractmethod
    #Probe 클래스를 사용하여 여러 Probe 객체를 만들어내는 역할
    def _probes(self, target: Target) -> Iterable[Probe]:
        """후보 (파라미터, 페이로드) 묶음을 만들어낸다."""

    #Finding 객체를 만드는 역할
    @abstractmethod
    def _build_finding(
        self,
        target: Target,
        probe: Probe,
        signature_hit: bytes,
        request_kwargs: dict[str, Any],
        response: HttpResponse,
    ) -> Finding: ...

    # ---- 내부 -------------------------------------------------------------

    # 주입 대상 파라미터 목록 반환
    def _candidate_params(self, target: Target) -> list[str]:
        if target.inject_params:
            return list(target.inject_params)
        if target.method.upper() == "GET":
            return list((target.params or {}).keys())
        #POST : body 값에 담긴 파라미터도 후보로 고려
        return list((target.data or {}).keys())

    #Target 스캔 실행 및 ScanReport 생성
    def _run_with_report(self, target: Target) -> ScanReport:
        if target.headers is None:
            target.headers = {}
        self._session_headers = target.headers  # run() / run_json() 양쪽에서 재로그인 Cookie 반영
        started = _now_iso()
        wall_start = time.perf_counter() #스캔 소요 시간 check 용

        findings: list[Finding] = []
        requests_made = 0  #실제 보낸 요청 수
        errors = 0

        is_partial = False
        #입력값 주입을 할 곳이 있을 때만 스캔 진행
        if self._candidate_params(target):
            probes = list(self._probes(target))

            # payload_limit은 파라미터별 페이로드 수 제한
            if self.payload_limit is not None:
                by_param: dict[str, list[Probe]] = {}
                for p in probes:
                    by_param.setdefault(p.parameter, []).append(p)
                limited = []
                for param_probes in by_param.values():
                    limited.extend(param_probes[: self.payload_limit])
                if len(limited) < len(probes):
                    is_partial = True
                probes = limited

            #병렬 실행 준비
            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = [ex.submit(self._probe_one, target, p) for p in probes]
                #실행이 끝나는 대로 결과 수집
                try:
                    for fut in as_completed(futures):
                        resp, finding = fut.result()
                        requests_made += 1
                        if not resp.ok:
                            errors += 1
                        if finding is not None:
                            findings.append(finding)
                            # 첫 finding 발견 시 pending 상태 future 취소 후 중단
                            for f in futures:
                                f.cancel()
                            break
                except KeyboardInterrupt:
                    for f in futures:
                        f.cancel()
                    raise

        # 심각도 내림차순, 동일 심각도 내에서는 신뢰도 내림차순
        findings.sort(
            key=lambda f: (severity_rank(f.severity), confidence_rank(f.confidence)),
            reverse=True,
        )


        finished = _now_iso()
        elapsed_ms = (time.perf_counter() - wall_start) * 1000.0

        if findings:
            status = ScanStatus.VULNERABLE
        elif is_partial:
            status = ScanStatus.PARTIAL
        else:
            status = ScanStatus.SAFE

        return ScanReport(
            module=self.name,
            target_url=target.url,
            started_at=started,
            finished_at=finished,
            status=status,
            findings=findings,
            stats={
                "requests": requests_made,
                "errors": errors,
                "elapsed_ms": round(elapsed_ms, 3),
            },
        )

    #Probe 하나를 실제로 실행하는 함수
    def _probe_one(
        self,
        target: Target,
        probe: Probe,
    ) -> tuple[HttpResponse, Finding | None]:
        #특정 파라미터에 페이로드를 주입
        kwargs = inject(target, probe.payload_value, probe.parameter)
        # 요청 전에 버전을 캡처 — "이 쿠키로 보낸 요청"의 기준점
        session_ver = self._session_version
        #실제로 요청 전송
        resp = self.http.request(**kwargs)
        if _needs_reauth(resp):
            from ksj_login import has_credentials
            if not has_credentials():
                # 저장된 자격증명 없음 — 부모 DAST에 재인증 요청 신호
                raise AuthenticationError(resp.status_code)
            # 세션 만료 — ksj_login으로 재로그인 후 한 번 재시도
            self._refresh_session(session_ver)
            kwargs = inject(target, probe.payload_value, probe.parameter)  # 갱신된 Cookie 반영
            resp = self.http.request(**kwargs)
            if _needs_reauth(resp):
                raise AuthenticationError(resp.status_code)
        #응답이 실패하면, finding 없이 끝내기
        if not resp.ok:
            return resp, None
        #응답에서 시그니처 매칭 시도
        sig = match(resp.body, probe.signatures)
        #시그니처 없으면 취약점 없음으로 처리
        if sig is None:
            return resp, None
        #시그니처 있으면 Finding 객체 만들어서 반환
        return resp, self._build_finding(target, probe, sig, kwargs, resp)

    def _refresh_session(self, session_version: int) -> None:
        """ksj_login으로 재로그인해 세션을 갱신한다. 다른 스레드가 이미 갱신했으면 건너뛴다."""
        with self._relogin_lock:
            # 다른 스레드가 먼저 갱신 완료한 경우 재로그인 불필요
            if self._session_version != session_version:
                return
            new_result = asyncio.run(_do_relogin_async())
            if not new_result.success:
                raise AuthenticationError(401)
            from ksj_login import to_cookie_header
            self._session_headers["Cookie"] = to_cookie_header(new_result.cookies)
            # CSRF 쿠키가 바뀌었으면 대응 헤더도 갱신 — 이미 있는 헤더 키만 업데이트
            _CSRF_MAP = {
                "csrftoken":  "X-CSRFToken",
                "XSRF-TOKEN": "X-XSRF-TOKEN",
                "csrf_token": "X-CSRF-Token",
                "_csrf":      "X-CSRF-Token",
            }
            new_cookie_values = {
                c["name"]: c["value"] for c in new_result.cookies if c.get("name")
            }
            for cookie_name, header_name in _CSRF_MAP.items():
                if cookie_name in new_cookie_values and header_name in self._session_headers:
                    self._session_headers[header_name] = new_cookie_values[cookie_name]
            self._session_version += 1
