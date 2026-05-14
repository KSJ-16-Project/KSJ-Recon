"""공통 예외 클래스."""


class AuthenticationError(Exception):
    """인증 만료 또는 인증 필요 상태"""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"authentication required (HTTP {status_code})")
