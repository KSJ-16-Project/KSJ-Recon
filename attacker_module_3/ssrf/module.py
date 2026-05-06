"""SSRF 공격 모듈."""
from __future__ import annotations

from typing import Any, Iterable

from attacker_module_3.common.base import AttackModule, Probe
from attacker_module_3.common.http import HttpResponse
from attacker_module_3.common.result import Finding, Severity
from attacker_module_3.common.target import Target

from attacker_module_3.ssrf.payloads import PAYLOADS


class SSRFModule(AttackModule):
    name = "ssrf"

    def _probes(self, target: Target) -> Iterable[Probe]:
        # 활성 페이로드는 모두 시그니처 매칭이 명확한 고-신뢰 케이스이므로
        # 매칭 시 일괄 CRITICAL 로 처리한다
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
            title=f"SSRF via {probe.parameter}: {probe.category}",
            target_url=target.url,
            method=target.method,
            parameter=probe.parameter,
            payload=probe.payload_value,
            evidence=signature_hit.decode("latin-1", errors="replace"),
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
