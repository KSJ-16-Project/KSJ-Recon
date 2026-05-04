"""결과 자료형 정의: Severity, Confidence, Finding, ScanReport."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# 취약점 심각도
class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# 시그니처 기반 결과 신뢰도
class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# 결과 정렬용
_SEVERITY_RANK = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
_CONFIDENCE_RANK = {Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}


def severity_rank(s: Severity) -> int:
    return _SEVERITY_RANK[s]


def confidence_rank(c: Confidence) -> int:
    return _CONFIDENCE_RANK[c]


# 취약점 발견 결과 하나 의미
@dataclass
class Finding:
    module: str
    severity: Severity
    confidence: Confidence
    title: str
    target_url: str
    method: str
    parameter: str
    payload: str
    evidence: str
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)

    # 결과를 JSON으로 변환
    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "title": self.title,
            "target_url": self.target_url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
        }


# 한 번의 모듈 실행 결과 전체 보고서
@dataclass
class ScanReport:
    module: str
    target_url: str
    started_at: str
    finished_at: str
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    # 보고서를 JSON으로 변환
    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "target_url": self.target_url,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
        }
