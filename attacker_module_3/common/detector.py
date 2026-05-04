"""응답 분석 헬퍼 — 시그니처 매칭과 베이스라인 비교."""
from __future__ import annotations

from typing import Any, Iterable

from common.http import HttpResponse

#base.py의 _probe_one에서 사용되는 시그니처 매칭 함수
def match(body: bytes, signatures: Iterable[bytes]) -> bytes | None:
    #응답 body 안에 시그니처가 있는지 확인 
    for sig in signatures:
        #시그니처가 있으면 반환, 없으면 None 반환
        if sig and sig in body:
            return sig
    return None


#베이스라인과 후보 응답을 비교하여 차이점 계산
def baseline_diff(baseline: HttpResponse, candidate: HttpResponse) -> dict[str, Any]:
    return {
        #응답코드 변화 확인
        "status_changed": baseline.status_code != candidate.status_code,
        #응답 본문 길이 차이 계산
        "length_delta": len(candidate.body) - len(baseline.body),
        #응답 시간 차이 계산
        "elapsed_delta_ms": candidate.elapsed_ms - baseline.elapsed_ms,
    }
