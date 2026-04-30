"""Layer B 인증 레이어 데이터 모델."""

from dataclasses import dataclass, field


@dataclass
class AuthConfig:
    """사용자가 CLI/설정으로 주입하는 인증 옵션."""
    username: str
    password: str
    success_url_pattern: str = ""   # 선택: 로그인 성공 URL 정규식


@dataclass
class AuthResult:
    """로그인 시도 결과. success=False여도 크롤은 graceful하게 진행됨."""
    success: bool
    login_url: str = ""
    cookies: list[dict] = field(default_factory=list)   # Playwright ctx.cookies() 포맷
    error: str = ""


@dataclass
class FormSelectors:
    """form_analyzer.py가 산출한 Playwright 셀렉터 묶음."""
    username: str
    password: str
    submit: str
