"""Conditional Playwright verification for high-risk candidates."""

from __future__ import annotations

import html
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .browser_engine import BrowserExecutionEngine
from .payloads import CONTEXT_PAYLOADS, WAF_BYPASS_PAYLOADS

logger = logging.getLogger(__name__)


class BrowserVerifier:
    def __init__(
        self,
        timeout_ms: int = 8000,
        auth_cookies: dict | None = None,
        auth_headers: dict | None = None,
        verify_tls: bool = False,
    ):
        self.timeout_ms = timeout_ms
        self._auth_cookies: dict = auth_cookies or {}
        self._auth_headers: dict = auth_headers or {}
        self._verify_tls = verify_tls
        self.engine = BrowserExecutionEngine(
            timeout_ms=timeout_ms,
            verify_tls=verify_tls,
            auth_cookies=self._auth_cookies,
            auth_headers=self._auth_headers,
        )
        self.errors: list[dict] = []

    def verify(self, findings: list[dict]) -> list[dict]:
        candidates = [
            f for f in findings
            if f.get("browser_verification_required") and not f.get("browser_verified")
        ]
        if not candidates:
            return findings
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except ImportError:
            for f in candidates:
                f["browser_verified"] = False
                f["verification_status"] = "browser_error"
                f.setdefault("evidence", {})["browser_error"] = "playwright_not_installed"
                self.errors.append(self._error(
                    f, phase="browser_verification", error="playwright_not_installed",
                    detail="pip install playwright && playwright install chromium",
                ))
            return findings

        # Single sync_playwright context for all findings avoids repeated Node.js
        # process restarts and prevents TargetClosedError races on browser.close().
        try:
            with self.engine.launch() as browser:
                for f in candidates:
                    self._verify_one(browser, f)
        except Exception as e:
            status, detail = self.engine.normalize_error(e)
            for f in candidates:
                if not f.get("browser_verified"):
                    f["browser_verified"] = False
                    f["verification_status"] = status
                    f.setdefault("evidence", {})["browser_error"] = detail
                    self.errors.append(self._error(
                        f, phase="browser_verification", error="browser_launch_failed",
                        detail=detail, verification_status=status,
                    ))
        return findings

    def _verify_one(self, browser, finding: dict) -> None:
        xss_type = finding.get("type")
        if xss_type == "reflected_xss_candidate":
            self._verify_reflected(browser, finding)
        elif xss_type == "reflected_xss_post_candidate":
            self._verify_post_reflected(browser, finding)
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
            ok, action = self._try_reflected_payload(browser, finding, payload)
            if ok:
                finding["browser_verified"] = True
                finding["verification_status"] = "verified"
                finding["risk"] = "HIGH"
                finding["payload"] = payload
                ev = finding.setdefault("evidence", {})
                ev["browser_reason"] = "alert_hook_triggered"
                ev["browser_action"] = action
                return
        finding["browser_verified"] = False
        if finding.get("verification_status") not in {"browser_error", "timeout", "auth_failed"}:
            finding["verification_status"] = "not_triggered"
        finding.setdefault("evidence", {})["browser_reason"] = "payloads_tested_but_no_alert_hook"

    def _try_reflected_payload(self, browser, finding: dict, payload: str) -> tuple[bool, str]:
        url = self._payload_url(finding["url"], finding["param"], payload)
        context = None
        triggered = False
        alert_text = None
        action = "page_load"
        try:
            with self.engine.context(
                browser,
                url=finding.get("url"),
                headers=finding.get("headers", {}),
                cookies=finding.get("cookies", {}),
            ) as context:
                page = context.new_page()
                self.engine.install_alert_capture(page)
                page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                self.engine.wait_for_alert_capture(page, timeout_ms=2000)
                triggered, alert_text = self.engine.read_alert_capture(page)

                view_url = finding.get("view_url")
                if not triggered and view_url and view_url != finding.get("url"):
                    url = self._payload_url(view_url, finding["param"], payload)
                    action = "view_url_page_load"
                    page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                    self.engine.wait_for_alert_capture(page, timeout_ms=2000)
                    triggered, alert_text = self.engine.read_alert_capture(page)

                if not triggered and finding.get("context") == "url_context":
                    action = "click_javascript_href"
                    clicked = self._click_javascript_href(page, finding)
                    if clicked:
                        self.engine.wait_for_alert_capture(page, timeout_ms=800)
                        triggered, alert_text = self.engine.read_alert_capture(page)

                self._write_browser_evidence(finding, triggered, alert_text, payload, url, action)
        except Exception as e:
            status, detail = self.engine.normalize_error(e)
            finding["verification_status"] = status
            finding.setdefault("evidence", {})["browser_error"] = detail
            self.errors.append(self._error(
                finding, phase="browser_verification", error=status,
                detail=detail, verification_status=status,
            ))
            self._write_browser_evidence(finding, triggered, alert_text, payload, url, action)
        return triggered, action

    # ------------------------------------------------------------------ #
    #  POST param reflected XSS                                           #
    # ------------------------------------------------------------------ #

    def _verify_post_reflected(self, browser, finding: dict) -> None:
        """Verify reflected XSS where the payload must be sent in POST body.

        GET verification can place the payload in the URL query string.  POST
        findings need a separate path because the payload belongs in either a
        form-encoded body or a JSON body.
        """
        context = finding.get("context") or "unknown"
        if finding.get("waf_detected") and finding.get("waf_bypass_payload"):
            payloads = [finding["waf_bypass_payload"]] + WAF_BYPASS_PAYLOADS.get(context, WAF_BYPASS_PAYLOADS["unknown"])[:1]
        else:
            payloads = CONTEXT_PAYLOADS.get(context, CONTEXT_PAYLOADS["unknown"])

        for payload in payloads[:2]:
            ok, action = self._try_post_reflected_payload(browser, finding, payload)
            if ok:
                finding["browser_verified"] = True
                finding["verification_status"] = "verified"
                finding["risk"] = "HIGH"
                finding["payload"] = payload
                ev = finding.setdefault("evidence", {})
                ev["browser_reason"] = "alert_hook_triggered"
                ev["browser_action"] = action
                return
        finding["browser_verified"] = False
        if finding.get("verification_status") not in {"browser_error", "timeout", "auth_failed"}:
            finding["verification_status"] = "not_triggered"
        finding.setdefault("evidence", {})["browser_reason"] = "payloads_tested_but_no_alert_hook"

    def _try_post_reflected_payload(self, browser, finding: dict, payload: str) -> tuple[bool, str]:
        url = finding.get("url", "")
        body_format = finding.get("body_format", "form")
        param = finding.get("param")
        body = dict(finding.get("body_params") or finding.get("params") or {})
        if param:
            body[param] = payload

        triggered = False
        alert_text = None
        action = "post_json_fetch" if body_format == "json" else "post_form_submit"
        try:
            with self.engine.context(
                browser,
                url=finding.get("url"),
                headers=finding.get("headers", {}),
                cookies=finding.get("cookies", {}),
            ) as ctx:
                page = ctx.new_page()
                self.engine.install_alert_capture(page)
                if body_format == "json":
                    self._submit_json_post_and_render(page, url, body)
                else:
                    self._submit_form_post(page, url, body)

                self.engine.wait_for_alert_capture(page, timeout_ms=2000)
                triggered, alert_text = self.engine.read_alert_capture(page)

                view_url = finding.get("view_url")
                if not triggered and view_url and view_url != url:
                    action += "+view_url_page_load"
                    page.goto(view_url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                    url = view_url
                    self.engine.wait_for_alert_capture(page, timeout_ms=2000)
                    triggered, alert_text = self.engine.read_alert_capture(page)

                if not triggered and finding.get("context") == "url_context":
                    action += "+click_javascript_href"
                    clicked = self._click_javascript_href(page, finding)
                    if clicked:
                        self.engine.wait_for_alert_capture(page, timeout_ms=800)
                        triggered, alert_text = self.engine.read_alert_capture(page)

                self._write_browser_evidence(finding, triggered, alert_text, payload, url, action)
        except Exception as e:
            status, detail = self.engine.normalize_error(e)
            finding["verification_status"] = status
            finding.setdefault("evidence", {})["browser_error"] = detail
            self.errors.append(self._error(
                finding, phase="browser_verification", error=status,
                detail=detail, verification_status=status,
            ))
            self._write_browser_evidence(finding, triggered, alert_text, payload, url, action)
        return triggered, action

    def _submit_form_post(self, page, url: str, body: dict) -> None:
        inputs = []
        for key, value in body.items():
            inputs.append(
                f'<input type="hidden" name="{html.escape(str(key), quote=True)}" '
                f'value="{html.escape(str(value), quote=True)}">'
            )
        form_html = f"""
        <html><body>
        <form id="xss-post-form" method="POST" action="{html.escape(url, quote=True)}">
            {''.join(inputs)}
        </form>
        <script>document.getElementById('xss-post-form').submit();</script>
        </body></html>
        """
        page.set_content(form_html, wait_until="domcontentloaded", timeout=self.timeout_ms)
        try:
            page.wait_for_load_state("domcontentloaded", timeout=self.timeout_ms)
        except Exception:
            pass

    def _submit_json_post_and_render(self, page, url: str, body: dict) -> None:
        # A browser page must render the POST response for alert() execution.
        # We first navigate to the target origin, then POST JSON with fetch and
        # write the response HTML into the document.
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
        except Exception:
            # Some POST endpoints do not support GET; fetch may still work if the
            # browser can create a document context.
            page.goto("about:blank", wait_until="domcontentloaded", timeout=self.timeout_ms)
        response_text = page.evaluate(
            """async ({url, body}) => {
                const res = await fetch(url, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(body),
                    credentials: 'include'
                });
                return await res.text();
            }""",
            {"url": url, "body": body},
        )
        page.set_content(response_text, wait_until="domcontentloaded", timeout=self.timeout_ms)

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
            ok = self._try_header_payload(browser, url, header_name, payload, finding)
            if ok:
                finding["browser_verified"] = True
                finding["verification_status"] = "verified"
                finding["risk"] = "HIGH"
                finding["payload"] = payload
                ev = finding.setdefault("evidence", {})
                ev["browser_reason"] = "alert_hook_triggered"
                ev["browser_action"] = f"header_{header_name}_injected"
                return
        finding["browser_verified"] = False
        if finding.get("verification_status") not in {"browser_error", "timeout", "auth_failed"}:
            finding["verification_status"] = "not_triggered"
        finding.setdefault("evidence", {})["browser_reason"] = "payloads_tested_but_no_alert_hook"

    def _try_header_payload(self, browser, url: str, header_name: str, payload: str, finding: dict) -> bool:
        triggered = False
        alert_text = None
        try:
            with self.engine.context(
                browser,
                url=finding.get("url"),
                headers={**(finding.get("headers", {}) or {}), header_name: payload},
                cookies=finding.get("cookies", {}),
            ) as ctx:
                page = ctx.new_page()
                self.engine.install_alert_capture(page)
                page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                self.engine.wait_for_alert_capture(page, timeout_ms=2000)
                triggered, alert_text = self.engine.read_alert_capture(page)
                self._write_browser_evidence(finding, triggered, alert_text, payload, url, f"header_{header_name}_injected")
        except Exception as e:
            status, detail = self.engine.normalize_error(e)
            finding["verification_status"] = status
            finding.setdefault("evidence", {})["browser_error"] = detail
            self.errors.append(self._error(
                finding, phase="browser_verification", error=status,
                detail=detail, verification_status=status,
            ))
            self._write_browser_evidence(finding, triggered, alert_text, payload, url, f"header_{header_name}_injected")
        return triggered

    # ------------------------------------------------------------------ #
    #  Stored XSS                                                          #
    # ------------------------------------------------------------------ #

    def _verify_stored(self, browser, finding: dict) -> None:
        url = finding.get("url")
        if not url:
            return

        triggered = False
        alert_text = None
        action = "page_load"
        payload = finding.get("payload", "")
        try:
            with self.engine.context(
                browser,
                url=finding.get("url"),
                headers=finding.get("headers", {}),
                cookies=finding.get("cookies", {}),
            ) as ctx:
                page = ctx.new_page()
                self.engine.install_alert_capture(page)
                page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                self.engine.wait_for_alert_capture(page, timeout_ms=2000)

                if not triggered and finding.get("context") == "url_context":
                    action = "click_javascript_href"
                    clicked = self._click_javascript_href(page, finding)
                    if clicked:
                        self.engine.wait_for_alert_capture(page, timeout_ms=800)

                triggered, alert_text = self.engine.read_alert_capture(page)
                self._write_browser_evidence(finding, triggered, alert_text, payload, url, action)

            if triggered:
                finding["browser_verified"] = True
                finding["verification_status"] = "verified"
                finding["risk"] = "HIGH"
                ev = finding.setdefault("evidence", {})
                ev["browser_reason"] = "alert_hook_triggered"
                ev["browser_action"] = action
            else:
                # Explicitly mark as not verified so the field is always present.
                finding["browser_verified"] = False
                finding["verification_status"] = "not_triggered"
                finding.setdefault("evidence", {})["browser_reason"] = "no_alert_on_stored_check_url"
        except Exception as e:
            status, detail = self.engine.normalize_error(e)
            finding["verification_status"] = status
            finding.setdefault("evidence", {})["browser_error"] = detail
            self.errors.append(self._error(
                finding, phase="browser_verification", error=status,
                detail=detail, verification_status=status,
            ))
            self._write_browser_evidence(finding, triggered, alert_text, payload, url, action)

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

    def _write_browser_evidence(
        self,
        finding: dict,
        triggered: bool,
        alert_text: str | None,
        payload: str,
        target_url: str,
        action: str,
    ) -> None:
        ev = finding.setdefault("evidence", {})
        ev.update(self.engine.evidence(
            triggered=triggered,
            alert_text=alert_text,
            payload=payload,
            target_url=target_url,
            reflection_context=finding.get("context"),
            browser_action=action,
        ))

    def _error(
        self,
        finding: dict,
        *,
        phase: str,
        error: str,
        detail: str = "",
        verification_status: str | None = None,
    ) -> dict:
        return {
            "url": finding.get("url", ""),
            "phase": phase,
            "error": error,
            "detail": detail,
            "category": verification_status or "browser_error",
            "verification_status": verification_status or "browser_error",
        }
