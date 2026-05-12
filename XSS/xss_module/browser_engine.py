"""Shared headless Playwright execution helpers for XSS verification."""

from __future__ import annotations

from contextlib import contextmanager
from urllib.parse import urlparse


class BrowserExecutionEngine:
    def __init__(
        self,
        *,
        timeout_ms: int = 8000,
        verify_tls: bool = False,
        auth_cookies: dict | None = None,
        auth_headers: dict | None = None,
    ):
        self.timeout_ms = timeout_ms
        self.verify_tls = verify_tls
        self.auth_cookies = auth_cookies or {}
        self.auth_headers = auth_headers or {}

    @contextmanager
    def launch(self):
        from playwright.sync_api import sync_playwright

        browser = None
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True)
                yield browser
            finally:
                if browser:
                    try:
                        browser.close()
                    except Exception:
                        pass

    @contextmanager
    def context(self, browser, *, url: str | None = None, headers: dict | None = None, cookies: dict | None = None):
        ctx = None
        merged_headers = {**self.auth_headers, **(headers or {})}
        merged_cookies = {**self.auth_cookies, **(cookies or {})}
        ctx_kwargs: dict = {"ignore_https_errors": not self.verify_tls}
        if merged_headers:
            ctx_kwargs["extra_http_headers"] = merged_headers
        try:
            ctx = browser.new_context(**ctx_kwargs)
            if merged_cookies and url:
                ctx.add_cookies(self.to_playwright_cookies(merged_cookies, url))
            yield ctx
        finally:
            if ctx:
                try:
                    ctx.close()
                except Exception:
                    pass

    def install_alert_capture(self, page) -> None:
        script = r'''
        (() => {  // 즉시 실행 함수: 페이지에 스크립트가 삽입되면 바로 실행
          if (window.__xssAlertHookInstalled) return;  // 중복 설치 방지
          window.__xssAlertHookInstalled = true;  // alert 감지 훅 설치 여부 저장
          window.__xssAlertTriggered = false;  // alert/confirm/prompt 발생 여부 초기화
          window.__xssAlertText = null;  // 발생한 팝업 종류와 메시지 저장 변수 초기화
          const record = (kind, message) => {  // 팝업 발생 정보를 기록하는 공통 함수
            window.__xssAlertTriggered = true;  // 팝업이 발생했음을 표시
            window.__xssAlertText = kind + ':' + String(message ?? '');  // 팝업 종류와 메시지 저장
          };
          window.alert = (message) => { record('alert', message); };  // alert 호출을 가로채서 기록
          window.confirm = (message) => { record('confirm', message); return true; };  // confirm 호출 기록 후 true 반환
          window.prompt = (message, defaultValue) => { record('prompt', message); return defaultValue || ''; };  // prompt 호출 기록 후 기본값 반환
        })();
        '''
        try:
            page.add_init_script(script)  # 새 문서가 로드되기 전에 스크립트를 먼저 삽입
        except Exception:
            pass  # 삽입 실패 시에도 전체 탐지 흐름이 중단되지 않도록 무시
        try:
            page.evaluate(script)  # 이미 로드된 현재 페이지에도 즉시 스크립트 실행
        except Exception:
            pass  # 실행 실패 시에도 전체 스캔이 멈추지 않도록 무시

    def read_alert_capture(self, page) -> tuple[bool, str | None]:
        try:
            data = page.evaluate("() => ({ triggered: Boolean(window.__xssAlertTriggered), text: window.__xssAlertText || null })")
            return bool(data.get("triggered")), data.get("text")
        except Exception:
            return False, None

    def wait_for_alert_capture(self, page, timeout_ms: int | None = None) -> None:
        try:
            page.wait_for_function(
                "() => Boolean(window.__xssAlertTriggered)",
                timeout=timeout_ms or self.timeout_ms,
            )
        except Exception:
            pass

    def normalize_error(self, exc: Exception) -> tuple[str, str]:
        text = str(exc)
        lowered = text.lower()
        if "timeout" in lowered:
            return "timeout", text
        _AUTH_SIGNALS = ("401", "403", "auth", "로그인", "세션 만료", "session expired", "please log in")
        if any(s in lowered for s in _AUTH_SIGNALS):
            return "auth_failed", text
        return "browser_error", text

    def evidence(
        self,
        *,
        triggered: bool,
        alert_text: str | None,
        payload: str | None,
        target_url: str | None,
        method: str = "browser_playwright",
        **extra,
    ) -> dict:
        data = {
            "alert_triggered": bool(triggered),
            "alert_text": alert_text,
            "executed_payload": payload,
            "target_url": target_url,
            "verification_method": method,
        }
        data.update(extra)
        return data

    def to_playwright_cookies(self, cookies: dict, url: str) -> list[dict]:
        if not cookies or not url:
            return []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        return [{"name": str(k), "value": str(v), "url": base_url} for k, v in cookies.items()]
