"""DOM Stored XSS verifier – Playwright-based form interaction.

Submits payloads into visible text inputs, revisits the page, and confirms
execution via alert dialog. Targets localStorage-based stored DOM XSS.

Only targets with type='form' AND safe_to_submit=True are tested.

Requires playwright: pip install playwright && playwright install chromium
"""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlparse

from .payloads import CONTEXT_PAYLOADS
from .result_builder import ResultBuilder

logger = logging.getLogger(__name__)


class DOMStoredXSSVerifier:
    def __init__(self, targets: list[dict], builder: ResultBuilder, evidence_dir: Path):
        self.targets = targets
        self.builder = builder
        self.evidence_dir = evidence_dir
        self.errors: list[dict] = []

    def scan(self) -> list[dict]:
        form_targets = [
            t for t in self.targets
            if t.get("type") == "form" and t.get("safe_to_submit")
        ]
        if not form_targets:
            logger.info("no form targets with safe_to_submit – dom_stored_xss skipped")
            return []

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            logger.warning("playwright not installed – dom_stored_xss skipped (pip install playwright && playwright install chromium)")
            self.errors.append(self.builder.error(
                url="N/A",
                phase="dom_stored_xss",
                error="playwright_not_installed",
                detail="pip install playwright && playwright install chromium",
            ))
            return []

        findings: list[dict] = []
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                for target in form_targets:
                    result = self._scan_target(browser, target)
                    if result:
                        findings.append(result)
                browser.close()
        except Exception as e:
            logger.error("dom_stored_xss browser error: %s", e)
            self.errors.append(self.builder.error(
                url="N/A",
                phase="dom_stored_xss",
                error="browser_launch_failed",
                detail=str(e),
            ))

        logger.info("dom_stored_xss findings: %d", len(findings))
        return findings

    def _scan_target(self, browser, target: dict) -> dict | None:
        url = target.get("url", "")
        if not url:
            return None
        cookies = target.get("cookies") or {}
        headers = target.get("headers") or {}
        for payload in CONTEXT_PAYLOADS["html_body"]:
            result = self._try_payload(browser, url, payload, cookies, headers)
            if result:
                return result
        return None

    def _try_payload(self, browser, url: str, payload: str, cookies: dict, headers: dict) -> dict | None:
        ctx = browser.new_context(ignore_https_errors=True)

        if cookies:
            domain = urlparse(url).netloc
            ctx.add_cookies([
                {"name": k, "value": v, "domain": domain, "path": "/"}
                for k, v in cookies.items()
            ])
        if headers:
            ctx.set_extra_http_headers(headers)

        page = ctx.new_page()
        alert_fired = False
        param_name = "form_input"

        def handle_dialog(dialog):
            nonlocal alert_fired
            alert_fired = True
            try:
                dialog.accept()
            except Exception:
                pass

        page.on("dialog", handle_dialog)

        try:
            page.goto(url, timeout=10000, wait_until="domcontentloaded")
            page.wait_for_timeout(500)

            # Find first visible and enabled text input
            input_field = None
            for selector in [
                'textarea',
                'input[type="text"]',
                'input[type="search"]',
                'input:not([type])',
            ]:
                for elem in page.query_selector_all(selector):
                    try:
                        if elem.is_visible() and elem.is_enabled():
                            input_field = elem
                            param_name = elem.get_attribute("name") or "form_input"
                            break
                    except Exception:
                        continue
                if input_field:
                    break

            if not input_field:
                return None

            input_field.fill(payload)

            submitted = False
            for sel in [
                'input[type="submit"]',
                'button[type="submit"]',
                'button',
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
                return None

            page.wait_for_timeout(1000)
            # Revisit to trigger localStorage-based replay
            page.goto(url, timeout=10000, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)

            if alert_fired:
                logger.info("dom_stored_xss confirmed: %s [%s]", url, param_name)
                return self.builder.finding(
                    type="dom_stored_xss_confirmed",
                    url=url,
                    method="DOM",
                    param=param_name,
                    marker=None,
                    reflected=True,
                    context="html_body",
                    escaped=False,
                    payload=payload,
                    browser_verified=True,
                    browser_verification_required=False,
                    risk="HIGH",
                    evidence={
                        "reason": "alert triggered after form submission and page revisit",
                        "scope_note": "localStorage-based stored DOM XSS suspected",
                    },
                )
        except Exception as e:
            logger.debug("dom_stored_xss attempt error: %s – %s", url, e)
        finally:
            try:
                page.remove_listener("dialog", handle_dialog)
            except Exception:
                pass
            try:
                ctx.close()
            except Exception:
                pass

        return None
