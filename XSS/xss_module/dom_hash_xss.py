"""Optional hash/fragment-based DOM XSS verifier.

This is not full DOM XSS data-flow analysis. It only verifies cases where a
candidate page can be tested by navigating to URL#payload and watching for a
browser dialog.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urldefrag, urlparse, quote
from datetime import datetime

from .payloads import DOM_HASH_PAYLOADS
from .result_builder import ResultBuilder


class DOMHashXSSVerifier:
    def __init__(self, targets: list[dict], builder: ResultBuilder, evidence_dir: Path, timeout_ms: int = 8000):
        self.targets = targets
        self.builder = builder
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_ms = timeout_ms
        self.errors: list[dict] = []

    def scan(self) -> list[dict]:
        candidate_urls = self._candidate_urls()
        if not candidate_urls:
            return []
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.errors.append(self.builder.error(url="", phase="dom_hash", error="playwright_not_installed"))
            return []

        findings = []
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            for url in candidate_urls:
                finding = self._test_url(browser, url)
                if finding:
                    findings.append(finding)
            browser.close()
        return findings

    def _candidate_urls(self) -> list[str]:
        urls = []
        for t in self.targets:
            url = t.get("url", "")
            if not url:
                continue
            base, frag = urldefrag(url)
            # Prefer URLs that already use fragments, or are explicitly marked.
            if frag or t.get("type") == "dom_hash":
                if base not in urls:
                    urls.append(base)
        return urls

    def _test_url(self, browser, base_url: str) -> dict | None:
        for payload in DOM_HASH_PAYLOADS:
            triggered, screenshot = self._try_payload(browser, base_url, payload)
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
                    evidence={
                        "browser_reason": "alert_dialog_triggered_after_url_fragment_payload",
                        "tested_url_pattern": f"{base_url}#<payload>",
                        "screenshot": str(screenshot) if screenshot else None,
                        "scope_note": "hash-based DOM XSS only; no general JavaScript data-flow tracing",
                    },
                )
        return None

    def _try_payload(self, browser, base_url: str, payload: str) -> tuple[bool, Path | None]:
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        triggered = False
        screenshot = None

        def on_dialog(dialog):
            # Keep the dialog handler minimal to avoid TargetClosedError races.
            nonlocal triggered
            triggered = True
            try:
                dialog.accept()
            except Exception as e:
                self.errors.append(self.builder.error(
                    url=base_url,
                    phase="dom_hash",
                    error="dialog_accept_error",
                    detail=str(e),
                ))

        page.on("dialog", on_dialog)
        try:
            page.goto(f"{base_url}#{quote(payload, safe="'()=:/;")}", wait_until="domcontentloaded", timeout=self.timeout_ms)
            page.wait_for_timeout(1200)
            if triggered:
                screenshot = self._screenshot_path(base_url)
                try:
                    page.screenshot(path=str(screenshot), full_page=True)
                except Exception:
                    screenshot = None
        except Exception as e:
            self.errors.append(self.builder.error(url=base_url, phase="dom_hash", error="browser_error", detail=str(e)))
        finally:
            try:
                page.remove_listener("dialog", on_dialog)
            except Exception:
                pass
            try:
                page.close()
            except Exception:
                pass
            try:
                context.close()
            except Exception:
                pass
        return triggered, screenshot

    def _screenshot_path(self, url: str) -> Path:
        host = (urlparse(url).netloc or "target").replace(":", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self.evidence_dir / f"{ts}_{host}_dom_hash_alert.png"
