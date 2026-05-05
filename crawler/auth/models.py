"""Data models for the crawler authentication layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AuthConfig:
    """User-supplied authentication options."""

    username: str = ""
    password: str = ""
    success_url_pattern: str = ""
    enabled: bool = True


@dataclass
class FormSelectors:
    """Playwright selectors inferred from a login form."""

    username: str
    password: str
    submit: str


@dataclass
class AuthResult:
    """Result of the optional authentication layer."""

    success: bool
    attempted: bool = False
    login_url: str = ""
    final_url: str = ""
    cookies: list[dict] = field(default_factory=list)
    local_storage: dict = field(default_factory=dict)
    session_storage: dict = field(default_factory=dict)
    selectors: Optional[FormSelectors] = None
    reason: str = ""
    error: str = ""
    login_requests: list = field(default_factory=list)  # 로그인 과정 POST 요청 전체
