"""DOM Stored XSS verifier – Playwright-based form interaction.

Submits payloads into visible text inputs, revisits the page, and confirms
execution via the window.alert hook. Targets localStorage-based stored DOM XSS.

Only targets with type='form' AND safe_to_submit=True are tested.

Requires playwright: pip install playwright && playwright install chromium
"""

from __future__ import annotations

import logging
from .browser_engine import BrowserExecutionEngine
from .payloads import new_marker
from .result_builder import ResultBuilder

logger = logging.getLogger(__name__)


def _alert_matches(alert_text: str | None, expected_alert_number: int | None) -> bool:
    if expected_alert_number is None or not alert_text:
        return False
    kind, sep, value = str(alert_text).partition(":")
    return sep == ":" and kind in {"alert", "confirm", "prompt"} and value == str(expected_alert_number)


class DOMStoredXSSVerifier:
    def __init__(
        self,
        targets: list[dict],
        builder: ResultBuilder,
        verify_tls: bool = False,
        timeout_ms: int = 8000,
        auth_cookies: dict | None = None,
        auth_headers: dict | None = None,
    ):
        self.targets = targets
        self.builder = builder
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
        self.skipped: list[dict] = []

    def scan(self) -> list[dict]:
        form_targets = []
        for target in self.targets:
            is_form_candidate = (
                target.get("type") == "form"
                or target.get("source") == "stored_targets"
            )
            if not is_form_candidate:
                continue
            if target.get("safe_to_submit"):
                form_targets.append(target)
                continue
            reason = "safe_to_submit is not explicitly true; DOM stored form submission skipped"
            logger.info("[dom_stored_xss] skipped unsafe target: %s (%s)", target.get("url", ""), reason)
            self.skipped.append(self.builder.finding(
                type="dom_stored_xss_skipped",
                url=target.get("url", ""),
                method="DOM",
                param=None,
                payload=None,
                risk="INFO",
                browser_verified=False,
                verification_status="skipped",
                evidence={
                    "reason": reason,
                    "safe_to_submit": bool(target.get("safe_to_submit", False)),
                    "verification_method": "not_run",
                },
            ))
        if not form_targets:
            logger.info("no form targets with safe_to_submit – dom_stored_xss skipped")
            return []

        try:
            from playwright.sync_api import sync_playwright as _  # noqa: F401
        except ImportError:
            logger.warning("playwright not installed – dom_stored_xss skipped (pip install playwright && playwright install chromium)")
            self.errors.append(self.builder.error(
                url="N/A", phase="dom_stored_xss",
                error="playwright_not_installed",
                detail="pip install playwright && playwright install chromium",
                category="browser_error",
            ))
            return []

        findings: list[dict] = []
        try:
            with self.engine.launch() as browser:
                for target in form_targets:
                    result = self._scan_target(browser, target)
                    if result:
                        findings.append(result)
        except Exception as e:
            status, detail = self.engine.normalize_error(e)
            logger.error("dom_stored_xss browser error: %s", e)
            self.errors.append(self.builder.error(
                url="N/A", phase="dom_stored_xss",
                error="browser_launch_failed", detail=detail,
                category=status, verification_status=status,
            ))

        logger.info("dom_stored_xss findings: %d", len(findings))
        return findings

    def _scan_target(self, browser, target: dict) -> dict | None:
        url = target.get("url", "")
        if not url:
            return None
        cookies = {**self._auth_cookies, **(target.get("cookies") or {})}
        headers = {**self._auth_headers, **(target.get("headers") or {})}
        logger.warning(
            "[dom_stored_xss] safe_to_submit=True – 실제 폼 제출이 발생합니다. "
            "테스트 데이터가 서버에 저장될 수 있습니다. (%s)", url,
        )
        cleanup_marker, alert_number = new_marker()  # Returns (marker, alert_number)
        for payload in self._payloads_with_marker(cleanup_marker, alert_number):
            result = self._try_payload(browser, url, payload, cookies, headers, cleanup_marker, alert_number)
            if result:
                return result
        return None

    def _payloads_with_marker(self, cleanup_marker: str, alert_number: int) -> list[str]:
        # Include the cleanup marker directly in the submitted payload so test
        # data can be identified and cleaned later.
        # Use different alert numbers for each payload variant
        return [
            f'<img data-testid="{cleanup_marker}" src=x onerror=alert({alert_number})>',
            f'<svg data-testid="{cleanup_marker}" onload=alert({alert_number})>',
            f'<script data-testid="{cleanup_marker}">alert({alert_number})</script>',
        ]

    def _try_payload(self, browser, url: str, payload: str, cookies: dict, headers: dict, cleanup_marker: str, alert_number: int) -> dict | None:
        param_name = "form_input"
        trigger_stage = None
        alert_text = None

        try:
            with self.engine.context(browser, url=url, headers=headers, cookies=cookies) as ctx:
                page = ctx.new_page()
                self.engine.install_alert_capture(page)
                page.goto(url, timeout=10000, wait_until="load")
                self._wait_for_client_form_ready(page)
                self.engine.wait_for_alert_capture(page, timeout_ms=500)

                # Collect ALL visible, enabled text inputs and fill each with the payload.
                # Filling all fields in one pass avoids multiple page reloads and covers
                # forms where the vulnerable field is not the first one.
                filled_inputs: list[str] = []
                first_filled_elem = None
                for selector in [
                    "textarea",
                    'input[type="text"]',
                    'input[type="search"]',
                    "input:not([type])",
                ]:
                    for elem in page.query_selector_all(selector):
                        try:
                            if elem.is_visible() and elem.is_enabled():
                                name = elem.get_attribute("name") or "form_input"
                                elem.fill(payload)
                                filled_inputs.append(name)
                                if first_filled_elem is None:
                                    first_filled_elem = elem
                        except Exception:
                            continue

                if not filled_inputs:
                    logger.debug("dom_stored_xss no fillable inputs: %s", url)
                    self.errors.append(self.builder.error(
                        url=url, phase="dom_stored_xss", error="selector_not_found",
                        detail="no visible enabled text input or textarea found",
                        category="selector_not_found", verification_status="selector_not_found",
                    ))
                    return None

                # Use the first filled field's name as the reported param
                param_name = filled_inputs[0]

                submitted = False
                if first_filled_elem:
                    try:
                        submitted = bool(first_filled_elem.evaluate(
                            """(el) => {
                              const form = el.form || el.closest('form');
                              if (!form) return false;
                              const submit = form.querySelector(
                                'input[type="submit"], button[type="submit"], button, input[type="button"]'
                              );
                              if (submit) {
                                submit.click();
                                return true;
                              }
                              if (form.requestSubmit) {
                                form.requestSubmit();
                                return true;
                              }
                              return form.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
                            }"""
                        ))
                    except Exception:
                        submitted = False

                if not submitted:
                    for sel in [
                        'input[type="submit"]',
                        'button[type="submit"]',
                        "button",
                        'input[type="button"]',
                    ]:
                        btn = page.query_selector(sel)
                        if btn:
                            try:
                                if btn.is_visible():
                                    btn.click()
                                    submitted = True
                                    break
                            except Exception:
                                continue

                if not submitted:
                    logger.debug("dom_stored_xss no submit control found: %s", url)
                    self.errors.append(self.builder.error(
                        url=url, phase="dom_stored_xss", error="submit_failed",
                        detail="no usable submit control or form submit path found",
                        category="submit_failed", verification_status="submit_failed",
                    ))
                    return None

                page.wait_for_timeout(250)
                self.engine.wait_for_alert_capture(page, timeout_ms=1000)

                hook_triggered, hook_text = self.engine.read_alert_capture(page)
                if hook_triggered:
                    # Verify alert matches expected alert number
                    if _alert_matches(hook_text, alert_number):
                        trigger_stage = "after_submit_same_document"
                        alert_text = hook_text
                    else:
                        logger.debug("dom_stored_xss alert triggered but unexpected value '%s' (expected %s)", hook_text, alert_number)
                        hook_triggered = False
                
                if not hook_triggered:
                    # Revisit to trigger persisted client-side replay. Reinstall the
                    # hook after navigation because a new document gets a fresh global.
                    self.engine.install_alert_capture(page)
                    page.goto(url, timeout=10000, wait_until="load")
                    self._wait_for_client_form_ready(page)
                    self.engine.wait_for_alert_capture(page, timeout_ms=2000)
                    hook_triggered, hook_text = self.engine.read_alert_capture(page)
                    if hook_triggered:
                        # Verify alert matches expected alert number
                        if _alert_matches(hook_text, alert_number):
                            trigger_stage = "after_revisit"
                            alert_text = hook_text
                        else:
                            logger.debug("dom_stored_xss alert triggered but unexpected value '%s' (expected %s)", hook_text, alert_number)
                            hook_triggered = False

                if trigger_stage:
                    logger.info("dom_stored_xss confirmed: %s [%s]", url, param_name)
                    return self.builder.finding(
                        type="dom_stored_xss_confirmed",
                        url=url,
                        method="DOM",
                        param=param_name,
                        marker=cleanup_marker,
                        cleanup_marker=cleanup_marker,
                        side_effect_possible=True,
                        stored_xss_submission_warning="실제 폼 제출이 발생할 수 있으며, 테스트 데이터가 서버에 저장될 수 있습니다.",
                        reflected=True,
                        context="html_body",
                        escaped=False,
                        payload=payload,
                        browser_verified=True,
                        browser_verification_required=False,
                        risk="HIGH",
                        verification_status="verified",
                        evidence=self.engine.evidence(
                            triggered=True,
                            alert_text=alert_text,
                            payload=payload,
                            target_url=url,
                            reason="alert hook triggered after form submission",
                            trigger_stage=trigger_stage,
                            filled_fields=filled_inputs,
                            scope_note="localStorage-based stored DOM XSS suspected",
                            cleanup_marker=cleanup_marker,
                            alert_capture_method="window_alert_hook",
                            side_effect_possible=True,
                            stored_xss_submission_warning="실제 폼 제출이 발생할 수 있으며, 테스트 데이터가 서버에 저장될 수 있습니다.",
                        ),
                    )
        except Exception as e:
            status, detail = self.engine.normalize_error(e)
            logger.debug("dom_stored_xss attempt error: %s – %s", url, e)
            self.errors.append(self.builder.error(
                url=url, phase="dom_stored_xss", error=status,
                detail=detail, category=status, verification_status=status,
            ))
        finally:
            pass

        return None

    def _wait_for_client_form_ready(self, page) -> None:
        """Wait briefly for client-side form setup to finish.

        Many DOM-stored XSS surfaces bind submit handlers after initial HTML
        parsing. Waiting for the full load event and a tiny stability window
        avoids submitting before framework or inline handlers are attached.
        """
        try:
            page.wait_for_load_state("load", timeout=2000)
        except Exception:
            pass
        try:
            page.wait_for_function(
                """() => {
                  if (document.readyState !== 'complete') return false;
                  const form = document.querySelector('form');
                  if (!form) return true;
                  return Boolean(form.querySelector(
                    'textarea, input[type="text"], input[type="search"], input:not([type])'
                  ));
                }""",
                timeout=2000,
            )
        except Exception:
            pass
        try:
            page.wait_for_timeout(100)
        except Exception:
            pass
