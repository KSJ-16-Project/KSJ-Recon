"""경로 순회 / 파일 다운로드 공격 모듈."""
from __future__ import annotations

from typing import Any, Iterable

from attacker_module_3.common.base import AttackModule, Probe
from attacker_module_3.common.http import HttpResponse
from attacker_module_3.common.result import Finding, Severity
from attacker_module_3.common.target import Target

from attacker_module_3.file_download.payloads import PAYLOADS


class FileDownloadModule(AttackModule):
    name = "file_download"
    stop_on_first_finding = True

    # 검사 후보 목록 생성
    def _probes(self, target: Target) -> Iterable[Probe]:
        # 활성 페이로드는 모두 /etc/passwd 회수 — 매칭 시 일괄 CRITICAL
        for parameter in self._candidate_params(target):
            for payload in PAYLOADS:
                yield Probe(
                    parameter=parameter,
                    payload_value=payload.value,
                    category=payload.category,
                    signatures=payload.signatures,
                    confidence=payload.confidence,
                    severity_when_signed=Severity.CRITICAL,
                )

    # 취약점 발견 시 결과 생성
    def _build_finding(
        self,
        target: Target,
        probe: Probe,
        signature_hit: bytes,
        request_kwargs: dict[str, Any],
        response: HttpResponse,
    ) -> Finding:
        return Finding(
            module=self.name,
            severity=probe.severity_when_signed,
            confidence=probe.confidence,
            title=f"Path traversal via {probe.parameter}: {probe.category}",
            target_url=target.url,
            method=target.method,
            parameter=probe.parameter,
            payload=probe.payload_value,
            evidence=signature_hit.decode("latin-1", errors="replace"),
            
            # 요청 정보 및 응답 정보 포함
            request={
                "url": request_kwargs["url"],
                "method": request_kwargs["method"],
                "params": request_kwargs.get("params") or None,
                "data": request_kwargs.get("data") or None,
            },
            response={
                "status": response.status_code,
                "elapsed_ms": round(response.elapsed_ms, 3),
                "length": len(response.body),
            },
        )
