"""Shared headless Playwright execution helpers for XSS verification."""

from __future__ import annotations

from contextlib import contextmanager
from urllib.parse import urlparse

VALID_VERIFICATION_STATUSES = {
    "verified",
    "not_triggered",
    "skipped",
    "browser_error",
    "timeout",
    "auth_failed",
    "selector_not_found",
    "submit_failed",
}


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
        (() => {
          if (window.__xssAlertHookInstalled) return;
          window.__xssAlertHookInstalled = true;
          window.__xssAlertTriggered = false;
          window.__xssAlertText = null;
          const record = (kind, message) => {
            window.__xssAlertTriggered = true;
            window.__xssAlertText = kind + ':' + String(message ?? '');
          };
          window.alert = (message) => { record('alert', message); };
          window.confirm = (message) => { record('confirm', message); return true; };
          window.prompt = (message, defaultValue) => { record('prompt', message); return defaultValue || ''; };
        })();
        '''
        try:
            page.add_init_script(script)
        except Exception:
            pass
        try:
            page.evaluate(script)
        except Exception:
            pass

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
        if "401" in lowered or "403" in lowered or "auth" in lowered:
            return "auth_failed", text
        return "browser_error", text

    def error_record(self, *, url: str, phase: str, exc: Exception | str, error: str | None = None) -> dict:
        if isinstance(exc, Exception):
            normalized, detail = self.normalize_error(exc)
        else:
            normalized, detail = "browser_error", str(exc)
        return {
            "url": url,
            "phase": phase,
            "error": error or normalized,
            "detail": detail,
            "category": normalized,
            "verification_status": normalized,
        }

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
