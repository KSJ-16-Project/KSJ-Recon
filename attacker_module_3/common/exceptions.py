"""공통 예외 클래스."""


class AuthenticationError(Exception):
    """401/403 응답으로 인증 실패가 확인됐을 때 발생."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"authentication required (HTTP {status_code})")
