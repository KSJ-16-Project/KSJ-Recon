"""Optional hash/fragment-based DOM XSS verifier.

This is not full DOM XSS data-flow analysis. It only verifies cases where a
candidate page can be tested by navigating to URL#payload and watching for a
window.alert hook trigger.
"""

from __future__ import annotations

from urllib.parse import urldefrag, quote
from typing import Callable
import logging

from .browser_engine import BrowserExecutionEngine
from .payloads import DOM_HASH_PAYLOADS
from .result_builder import ResultBuilder

logger = logging.getLogger(__name__)


class DOMHashXSSVerifier:
    def __init__(
        self,
        targets: list[dict],
        builder: ResultBuilder,
        timeout_ms: int = 8000,
        auth_refresher: Callable | None = None,
        verify_tls: bool = False,
        auth_cookies: dict | None = None,
        auth_headers: dict | None = None,
    ):
        self.targets = targets
        self.builder = builder
        self.timeout_ms = timeout_ms
        self.auth_refresher = auth_refresher  # reserved for future cookie refresh on 401
        self.verify_tls = verify_tls
        self._auth_cookies = auth_cookies or {}
        self._auth_headers = auth_headers or {}
        self.engine = BrowserExecutionEngine(
            timeout_ms=timeout_ms,
            verify_tls=verify_tls,
            auth_cookies=self._auth_cookies,
            auth_headers=self._auth_headers,
        )
        self.errors: list[dict] = []

    def scan(self) -> list[dict]:
        candidate_urls = self._candidate_urls()
        if not candidate_urls:
            return []
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.errors.append(self.builder.error(
                url="", phase="dom_hash", error="playwright_not_installed",
                category="browser_error",
            ))
            return []

        findings = []
        try:
            with self.engine.launch() as browser:
                for url in candidate_urls:
                    finding = self._test_url(browser, url)
                    if finding:
                        findings.append(finding)
        except Exception as e:
            status, detail = self.engine.normalize_error(e)
            self.errors.append(self.builder.error(
                url="", phase="dom_hash", error="browser_launch_failed",
                detail=detail, category=status, verification_status=status,
            ))
        return findings

    def _candidate_urls(self) -> list[str]:
        urls = []
        for t in self.targets:
            url = t.get("url", "")
            if not url:
                continue
            base, frag = urldefrag(url)
            if frag or t.get("type") == "dom_hash":
                if base not in urls:
                    urls.append(base)
        return urls

    def _test_url(self, browser, base_url: str) -> dict | None:
        for payload in DOM_HASH_PAYLOADS:
            triggered, alert_text, target_url = self._try_payload(browser, base_url, payload)
            if triggered:
                return self.builder.finding(
                    type="dom_hash_xss_verified",
                    url=base_url,
                    method="GET",
                    source="location.hash",
                    param="#fragment",
                    payload=payload,
                    browser_verified=True,
                    risk="HIGH",
                    verification_status="verified",
                    evidence=self.engine.evidence(
                        triggered=True,
                        alert_text=alert_text,
                        payload=payload,
                        target_url=target_url,
                        browser_reason="alert_hook_triggered_after_url_fragment_payload",
                        tested_url_pattern=f"{base_url}#<payload>",
                        alert_capture_method="window_alert_hook",
                        scope_note="hash-based DOM XSS only; no general JavaScript data-flow tracing",
                    ),
                )
        return None

    def _try_payload(self, browser, base_url: str, payload: str) -> tuple[bool, str | None, str]:
        # ignore_https_errors reflects the verify_tls option from scanner config
        ctx = None
        page = None
        triggered = False
        alert_text = None
        safe_chars = "'()=:/;"
        target_url = f"{base_url}#{quote(payload, safe=safe_chars)}"
        try:
            with self.engine.context(browser, url=base_url) as ctx:
                page = ctx.new_page()
                self.engine.install_alert_capture(page)
                page.goto(target_url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                self.engine.wait_for_alert_capture(page, timeout_ms=1200)
                hook_triggered, hook_text = self.engine.read_alert_capture(page)
                if hook_triggered:
                    triggered = True
                    alert_text = alert_text or hook_text
        except Exception as e:
            status, detail = self.engine.normalize_error(e)
            self.errors.append(self.builder.error(
                url=base_url, phase="dom_hash", error=status, detail=detail,
                category=status, verification_status=status,
            ))
        finally:
            pass
        return triggered, alert_text, target_url
