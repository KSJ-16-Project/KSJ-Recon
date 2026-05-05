"""모든 공격 모듈이 상속하는 공통 베이스 클래스."""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ClassVar, Iterable, Sequence

from common.detector import match
#HTTP 요청을 보내고 응답을 담는 공통 래퍼
from common.http import HttpClient, HttpResponse
from common.injector import inject
from common.exceptions import AuthenticationError
from common.io import dump_error, dump_report, load_request
from common.result import (
    Confidence,
    Finding,
    ScanReport,
    Severity,
    confidence_rank,
    severity_rank,
)
from common.target import Target


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

    # ---- 공개 API ---------------------------------------------------------

    # 공격 모듈 실행
    def run(self, target: Target) -> list[Finding]:
        """생성한 ScanReport에서 findings만 추출"""
        return list(self._run_with_report(target).findings)

    #부모 DAST 가 직접 호출하는 경로
    @classmethod
    def run_json(cls, request: str | bytes | bytearray | dict[str, Any]) -> str:
        """JSON-in / JSON-out 진입점."""
        try:
            req = load_request(request) #JSON 요청을 프로젝트 내부에서 쓰기 좋은 형태로 파싱
            http = HttpClient(**req.http_kwargs) #HTTP 클라이언트 생성
            module = cls(http=http, **req.module_kwargs) #공격 모듈 객체 생성
            report = module._run_with_report(req.target) #스캔 실행 후 JSON 반환
            return dump_report(report)
        except AuthenticationError as e:
            return dump_error("auth_required", e.status_code)
        except (ValueError, TypeError):
            return dump_error("invalid_request", 0)

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
        started = _now_iso()
        wall_start = time.perf_counter() #스캔 소요 시간 check 용

        findings: list[Finding] = []
        requests_made = 0  #실제 보낸 요청 수
        errors = 0

        #입력값 주입을 할 곳이 있을 때만 스캔 진행
        if self._candidate_params(target):
            probes = list(self._probes(target))
            
            #payload_limit이 설정되어 있으면 그 수만큼의 Probe만 사용
            if self.payload_limit is not None:
                probes = probes[: self.payload_limit]

            #병렬 실행 준비
            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = [ex.submit(self._probe_one, target, p) for p in probes]
                #실행이 끝나는 대로 결과 수집
                try:
                    for fut in as_completed(futures):
                        resp, finding = fut.result()
                        requests_made += 1
                        #결과가 이상하면 에러 추가
                        if not resp.ok:
                            errors += 1
                        #이미 finding이 만들어진 경우에는 기존 목록에 추가
                        if finding is not None:
                            findings.append(finding)
                except KeyboardInterrupt:
                    # 아직 시작 안 한 probe는 취소, 실행 중인 것은 자연 종료 대기
                    for f in futures:
                        f.cancel()
                    raise

        # 심각도 내림차순, 동일 심각도 내에서는 신뢰도 내림차순
        findings.sort(
            key=lambda f: (severity_rank(f.severity), confidence_rank(f.confidence)),
            reverse=True,
        )


        finished = _now_iso()
        #스캔에 걸린 시간 계산
        elapsed_ms = (time.perf_counter() - wall_start) * 1000.0
        #ScanReport 객체 생성하여 반환
        return ScanReport(
            module=self.name,
            target_url=target.url,
            started_at=started,
            finished_at=finished,
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
        #실제로 요청 전송
        resp = self.http.request(**kwargs)
        # 401/403 은 토큰 만료 — 부모 DAST에 재인증 요청 신호
        if resp.status_code in (401, 403):
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
