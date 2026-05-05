"""Conditional Playwright verification for high-risk candidates."""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime

from .payloads import CONTEXT_PAYLOADS, WAF_BYPASS_PAYLOADS

logger = logging.getLogger(__name__)


class BrowserVerifier:
    def __init__(self, evidence_dir: Path, timeout_ms: int = 8000):
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_ms = timeout_ms

    def verify(self, findings: list[dict]) -> list[dict]:
        candidates = [
            f for f in findings
            if f.get("browser_verification_required") and not f.get("browser_verified")
        ]
        if not candidates:
            return findings
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            for f in candidates:
                f["browser_verified"] = False
                f.setdefault("evidence", {})["browser_error"] = "playwright_not_installed"
            return findings

        for f in candidates:
            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True)
                    try:
                        self._verify_one(browser, f)
                    finally:
                        try:
                            browser.close()
                        except Exception:
                            pass
            except Exception as e:
                f.setdefault("evidence", {})["browser_error"] = str(e)
        return findings

    def _verify_one(self, browser, finding: dict) -> None:
        xss_type = finding.get("type")
        if xss_type == "reflected_xss_candidate":
            self._verify_reflected(browser, finding)
        elif xss_type == "header_reflected_xss_candidate":
            self._verify_header(browser, finding)
        elif xss_type == "stored_xss_candidate_limited":
            self._verify_stored(browser, finding)

    # ------------------------------------------------------------------ #
    #  GET param reflected XSS                                            #
    # ------------------------------------------------------------------ #

    def _verify_reflected(self, browser, finding: dict) -> None:
        context = finding.get("context") or "unknown"
        if finding.get("waf_detected") and finding.get("waf_bypass_payload"):
            payloads = [finding["waf_bypass_payload"]] + WAF_BYPASS_PAYLOADS.get(context, WAF_BYPASS_PAYLOADS["unknown"])[:1]
        else:
            payloads = CONTEXT_PAYLOADS.get(context, CONTEXT_PAYLOADS["unknown"])
        for payload in payloads[:2]:
            ok, screenshot, action = self._try_reflected_payload(browser, finding, payload)
            if ok:
                finding["browser_verified"] = True
                finding["risk"] = "HIGH"
                finding["payload"] = payload
                ev = finding.setdefault("evidence", {})
                ev["browser_reason"] = "alert_dialog_triggered"
                ev["browser_action"] = action
                if screenshot:
                    ev["screenshot"] = str(screenshot)
                return
        finding.setdefault("evidence", {})["browser_reason"] = "payloads_tested_but_no_dialog"

    def _try_reflected_payload(self, browser, finding: dict, payload: str) -> tuple[bool, Path | None, str]:
        url = self._payload_url(finding["url"], finding["param"], payload)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        triggered = False
        screenshot = None
        action = "page_load"

        def on_dialog(dialog):
            nonlocal triggered
            triggered = True
            try:
                dialog.dismiss()
            except Exception:
                pass

        page.on("dialog", on_dialog)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            page.wait_for_timeout(1000)

            if not triggered and finding.get("context") == "url_context":
                action = "click_javascript_href"
                clicked = self._click_javascript_href(page, finding)
                if clicked:
                    page.wait_for_timeout(800)

            if triggered:
                screenshot = self._screenshot_path(finding, "alert")
                try:
                    page.screenshot(path=str(screenshot), full_page=True)
                except Exception:
                    screenshot = None
        except Exception as e:
            finding.setdefault("evidence", {})["browser_error"] = str(e)
        finally:
            try:
                page.goto("about:blank", wait_until="domcontentloaded", timeout=3000)
            except Exception:
                pass
            try:
                context.close()
            except Exception:
                pass
        return triggered, screenshot, action

    # ------------------------------------------------------------------ #
    #  Header reflected XSS                                               #
    # ------------------------------------------------------------------ #

    def _verify_header(self, browser, finding: dict) -> None:
        header_name = finding.get("param")
        url = finding.get("url")
        if not header_name or not url:
            return

        payloads = CONTEXT_PAYLOADS.get(finding.get("context") or "unknown", CONTEXT_PAYLOADS["unknown"])
        for payload in payloads[:2]:
            ok, screenshot = self._try_header_payload(browser, url, header_name, payload, finding)
            if ok:
                finding["browser_verified"] = True
                finding["risk"] = "HIGH"
                finding["payload"] = payload
                ev = finding.setdefault("evidence", {})
                ev["browser_reason"] = "alert_dialog_triggered"
                ev["browser_action"] = f"header_{header_name}_injected"
                if screenshot:
                    ev["screenshot"] = str(screenshot)
                return
        finding.setdefault("evidence", {})["browser_reason"] = "payloads_tested_but_no_dialog"

    def _try_header_payload(self, browser, url: str, header_name: str, payload: str, finding: dict) -> tuple[bool, Path | None]:
        ctx = browser.new_context(
            ignore_https_errors=True,
            extra_http_headers={header_name: payload},
        )
        page = ctx.new_page()
        triggered = False
        screenshot = None

        def on_dialog(dialog):
            nonlocal triggered
            triggered = True
            try:
                dialog.dismiss()
            except Exception:
                pass

        page.on("dialog", on_dialog)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            page.wait_for_timeout(1000)
            if triggered:
                screenshot = self._screenshot_path(finding, "alert")
                try:
                    page.screenshot(path=str(screenshot), full_page=True)
                except Exception:
                    screenshot = None
        except Exception as e:
            finding.setdefault("evidence", {})["browser_error"] = str(e)
        finally:
            try:
                page.goto("about:blank", wait_until="domcontentloaded", timeout=3000)
            except Exception:
                pass
            try:
                ctx.close()
            except Exception:
                pass
        return triggered, screenshot

    # ------------------------------------------------------------------ #
    #  Stored XSS                                                          #
    # ------------------------------------------------------------------ #

    def _verify_stored(self, browser, finding: dict) -> None:
        url = finding.get("url")
        if not url:
            return

        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        triggered = False
        screenshot = None
        action = "page_load"

        def on_dialog(dialog):
            nonlocal triggered
            triggered = True
            try:
                dialog.dismiss()
            except Exception:
                pass

        page.on("dialog", on_dialog)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            page.wait_for_timeout(1000)

            if not triggered and finding.get("context") == "url_context":
                action = "click_javascript_href"
                clicked = self._click_javascript_href(page, finding)
                if clicked:
                    page.wait_for_timeout(800)

            if triggered:
                finding["browser_verified"] = True
                finding["risk"] = "HIGH"
                ev = finding.setdefault("evidence", {})
                ev["browser_reason"] = "alert_dialog_triggered"
                ev["browser_action"] = action
                screenshot = self._screenshot_path(finding, "alert")
                try:
                    page.screenshot(path=str(screenshot), full_page=True)
                    ev["screenshot"] = str(screenshot)
                except Exception:
                    pass
            else:
                finding.setdefault("evidence", {})["browser_reason"] = "no_alert_on_stored_check_url"
        except Exception as e:
            finding.setdefault("evidence", {})["browser_error"] = str(e)
        finally:
            try:
                page.goto("about:blank", wait_until="domcontentloaded", timeout=3000)
            except Exception:
                pass
            try:
                ctx.close()
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _click_javascript_href(self, page, finding: dict) -> bool:
        try:
            count = page.locator("a[href^='javascript:'], a[href^='JaVaScRiPt:']").count()
            if count <= 0:
                finding.setdefault("evidence", {})["click_reason"] = "no_javascript_href_found"
                return False
            href = page.locator("a[href^='javascript:'], a[href^='JaVaScRiPt:']").first.get_attribute("href")
            finding.setdefault("evidence", {})["click_target_href"] = href
            page.locator("a[href^='javascript:'], a[href^='JaVaScRiPt:']").first.click(timeout=self.timeout_ms)
            return True
        except Exception as e:
            finding.setdefault("evidence", {})["click_error"] = str(e)
            return False

    def _payload_url(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = {k: v[0] if v else "" for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        params[param] = payload
        return urlunparse(parsed._replace(query=urlencode(params)))

    def _screenshot_path(self, finding: dict, suffix: str) -> Path:
        parsed = urlparse(finding.get("url", ""))
        host = (parsed.netloc or "target").replace(":", "_")
        param = finding.get("param", "param")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self.evidence_dir / f"{ts}_{host}_{param}_{suffix}.png"
