"""Limited Stored XSS candidate detector.

This module intentionally only submits forms marked as safe_to_submit or forms
that look text-only and non-destructive. It checks whether a marker becomes
observable on configured check URLs or known crawled URLs.
"""

from __future__ import annotations

import logging
import time
import re
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
from urllib.parse import urljoin

from .browser_engine import BrowserExecutionEngine
from .context_analyzer import ContextAnalyzer
from .http_client import HttpClient
from .payloads import HIGH_VALUE_PARAM_NAMES, SPECIAL_PROBE, WAF_BYPASS_PAYLOADS, new_marker
from .result_builder import ResultBuilder
from .scanner_base import auth_failed, detect_waf, inject_csrf

logger = logging.getLogger(__name__)

VERIFIABLE_CONTEXTS = {
    "html_body",
    "html_attribute_double",
    "html_attribute_single",
    "html_attribute_unquoted",
    "event_handler_js",
    "event_handler_js_string_double",
    "event_handler_js_string_single",
    "js_block",
    "js_string_double",
    "js_string_single",
    "url_context",
    "html_comment",
}

STORED_XSS_SUBMISSION_WARNING = (
    "실제 폼 제출이 발생할 수 있으며, 테스트 데이터가 서버에 저장될 수 있습니다."
)


class StoredXSSScanner:
    def __init__(self, targets: list[dict], client: HttpClient, builder: ResultBuilder, auth_refresher=None):
        self.targets = targets
        self.client = client
        self.builder = builder
        self.auth_refresher = auth_refresher
        self.analyzer = ContextAnalyzer()
        self.errors: list[dict] = []
        self.skipped: list[dict] = []
        self.known_get_urls = [t["url"] for t in targets if t.get("method", "GET").upper() == "GET"]
        self.browser_engine = BrowserExecutionEngine(
            timeout_ms=max(1000, int(getattr(client, "timeout", 10)) * 1000),
            verify_tls=bool(getattr(client, "verify_tls", False)),
            auth_cookies={k: v for k, v in client.session.cookies.items()},
            auth_headers=dict(client.session.headers),
        )

    def scan(self) -> list[dict]:
        findings: list[dict] = []
        for target in self.targets:
            method = target.get("method", "GET").upper()
            params = target.get("params") or {}
            explicitly_stored_like = (
                target.get("source") == "stored_targets"
                or target.get("type") == "form"
                or method == "POST"
            )
            if explicitly_stored_like and method in ("GET", "POST") and params and not target.get("safe_to_submit"):
                reason = "safe_to_submit is not explicitly true; stored XSS submission skipped"
                logger.info("[stored_xss] skipped unsafe target: %s (%s)", target.get("url", ""), reason)
                self.skipped.append(self.builder.finding(
                    type="stored_xss_skipped",
                    url=target.get("url", ""),
                    method=method,
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
        candidates = [
            t for t in self.targets
            if t.get("method", "GET").upper() in ("GET", "POST")
            and t.get("safe_to_submit")
            and t.get("params")
        ]
        total = len(candidates)
        for i, target in enumerate(candidates):
            params = target.get("params") or {}
            logger.info("[%d/%d] stored scan: %s", i + 1, total, target["url"])
            for param in self._candidate_params(target, params):
                finding = self._test_form(target, params, param)
                if finding:
                    findings.append(finding)
        return findings

    def _is_verifiable_context(self, context: str | None) -> bool:
        # ContextAnalyzer returns concrete context names, not broad labels such
        # as "script" or "event_handler".  Keep this helper to avoid future
        # mismatch when context names are extended.
        return bool(context and context in VERIFIABLE_CONTEXTS)


    def _test_form(self, target: dict, params: dict, param: str) -> dict | None:
        cleanup_marker, alert_number = new_marker()  # Returns (marker, alert_number)
        marker = cleanup_marker
        # Keep a unique plain-text marker around the script payload so stored
        # views that sanitize tags but still render text remain detectable.
        # Each test gets a different alert number to avoid false positives from previous test data.
        payload = (
            f"{cleanup_marker}"
            f'<script data-testid="{cleanup_marker}">alert({alert_number})</script>'
            f"{cleanup_marker}"
        )
        data = dict(params)
        # Store a marker-bearing payload so later verification can both trigger
        # alert(1) and identify/clean the test data by cleanup_marker.
        data[param] = payload
        url = target["url"]
        method = target.get("method", "GET").upper()
        req_headers = target.get("headers") or {}
        req_cookies = target.get("cookies") or {}
        body_format = target.get("body_format", "form")

        logger.warning(
            "[stored_xss] safe_to_submit=True – 실제 폼 제출이 발생합니다. "
            "테스트 데이터가 서버에 저장될 수 있습니다. (%s)", url,
        )

        if method == "POST":
            inject_csrf(self.client, url, data, req_headers, req_cookies)

        try:
            submit_resp = self._submit(method, url, data, body_format, req_headers, req_cookies)
        except Exception as e:
            self.errors.append(self.builder.error(url=url, phase="stored_submit", error="request_failed", detail=str(e), category="network_error"))
            return None

        # 429 retry
        if submit_resp.status_code == 429:
            logger.warning("429 rate-limit on %s [%s] – retrying after 2s", url, param)
            time.sleep(2)
            if method == "POST":
                inject_csrf(self.client, url, data, req_headers, req_cookies)
            try:
                submit_resp = self._submit(method, url, data, body_format, req_headers, req_cookies)
            except Exception as e:
                self.errors.append(self.builder.error(url=url, phase="stored_submit", error="request_failed", detail=str(e), category="network_error"))
                return None
            if submit_resp.status_code == 429:
                self.errors.append(self.builder.error(url=url, phase="stored_submit", error="waf_rate_limited", detail="429 after retry", category="waf_block"))
                return None

        if auth_failed(submit_resp, original_url=url):
            if self.auth_refresher:
                self.auth_refresher()
                if method == "POST":
                    inject_csrf(self.client, url, data, req_headers, req_cookies)
                try:
                    submit_resp = self._submit(method, url, data, body_format, req_headers, req_cookies)
                except Exception as e:
                    self.errors.append(self.builder.error(url=url, phase="stored_submit_retry", error="request_failed", detail=str(e), category="network_error"))
                    return None
            if auth_failed(submit_resp, original_url=url):
                self.errors.append(self.builder.error(url=url, phase="stored_submit", error="auth_failed", detail=f"status={submit_resp.status_code}", category="auth_failed"))
                return None

        waf = detect_waf(submit_resp)

        # POST 응답 자체에 마커가 반영된 경우 먼저 처리 (제출 즉시 같은 페이지에 반영되는 저장형 XSS)
        submit_analysis = self._analyze_relaxed(submit_resp.text, marker)
        if submit_analysis.reflected:
            escaped = self._check_special_encoding(target, params, param, [url], marker)
            risk = "LOW" if escaped else "MEDIUM"
            bypass_payload = None
            if waf and not escaped:
                bypass_payload = self._find_waf_bypass(target, params, param, submit_analysis.context, req_headers, req_cookies, body_format)
            return self.builder.finding(
                type="stored_xss_candidate_limited",
                url=url,
                source_url=url,
                method=method,
                param=param,
                marker=marker,
                reflected=True,
                context=submit_analysis.context,
                escaped=escaped,
                payload=payload,
                alert_number=alert_number,
                cleanup_marker=cleanup_marker,
                side_effect_possible=True,
                stored_xss_submission_warning=STORED_XSS_SUBMISSION_WARNING,
                browser_verified=False,
                browser_verification_required=(not escaped) and self._is_verifiable_context(submit_analysis.context),
                verification_status="skipped",
                waf_detected=waf,
                waf_bypass_possible=bypass_payload is not None,
                waf_bypass_payload=bypass_payload,
                risk=risk,
                evidence={
                    "submit_status": submit_resp.status_code,
                    "checked_url": url,
                    "snippet": submit_analysis.snippet,
                    "reason": f"marker reflected in {method} response body (same-page stored XSS)",
                    "scope_note": "limited stored XSS check; not a full stored-XSS workflow crawler",
                    "cleanup_marker": cleanup_marker,
                    "side_effect_possible": True,
                    "stored_xss_submission_warning": STORED_XSS_SUBMISSION_WARNING,
                },
            )

        check_urls = self._check_urls(target, submit_resp.url)
        for check_url in check_urls:
            try:
                resp = self.client.get(check_url, headers=req_headers, cookies=req_cookies)
            except Exception:
                continue
            analysis = self._analyze_relaxed(resp.text, marker)
            if not analysis.reflected:
                continue

            escaped = self._check_special_encoding(target, params, param, check_urls, marker)
            risk = "LOW" if escaped else "MEDIUM"

            bypass_payload = None
            if waf and not escaped:
                bypass_payload = self._find_waf_bypass(target, params, param, analysis.context, req_headers, req_cookies, body_format)

            browser_verification_required = (not escaped) and self._is_verifiable_context(analysis.context)

            return self.builder.finding(
                type="stored_xss_candidate_limited",
                url=check_url,
                source_url=url,
                method=method,
                param=param,
                marker=marker,
                reflected=True,
                context=analysis.context,
                escaped=escaped,
                payload=payload,
                alert_number=alert_number,
                cleanup_marker=cleanup_marker,
                side_effect_possible=True,
                stored_xss_submission_warning=STORED_XSS_SUBMISSION_WARNING,
                browser_verified=False,
                browser_verification_required=browser_verification_required,
                verification_status="skipped",
                waf_detected=waf,
                waf_bypass_possible=bypass_payload is not None,
                waf_bypass_payload=bypass_payload,
                risk=risk,
                evidence={
                    "submit_status": submit_resp.status_code,
                    "checked_url": check_url,
                    "snippet": analysis.snippet,
                    "reason": f"marker submitted through a safe {method} form and later observed on a reachable page",
                    "scope_note": "limited stored XSS check; not a full stored-XSS workflow crawler",
                    "cleanup_marker": cleanup_marker,
                    "side_effect_possible": True,
                    "stored_xss_submission_warning": STORED_XSS_SUBMISSION_WARNING,
                },
            )

        # Fallback: when list/detail pages transform text and strict marker
        # matching fails, verify real JS execution in the browser.
        triggered, triggered_url, alert_text = self._browser_verify_stored(
            check_urls, req_headers, req_cookies, 
            expected_marker=cleanup_marker,
            expected_alert_number=alert_number
        )
        if triggered:
            return self.builder.finding(
                type="stored_xss_candidate_limited",
                url=triggered_url or (check_urls[0] if check_urls else url),
                source_url=url,
                method=method,
                param=param,
                marker=marker,
                reflected=False,
                context="unknown",
                escaped=False,
                payload=payload,
                cleanup_marker=cleanup_marker,
                side_effect_possible=True,
                stored_xss_submission_warning=STORED_XSS_SUBMISSION_WARNING,
                browser_verified=True,
                browser_verification_required=False,
                verification_status="verified",
                waf_detected=waf,
                waf_bypass_possible=False,
                waf_bypass_payload=None,
                risk="HIGH",
                evidence=self.browser_engine.evidence(
                    triggered=True,
                    alert_text=alert_text,
                    payload=payload,
                    target_url=triggered_url or (check_urls[0] if check_urls else url),
                    browser_reason="alert_hook_triggered_after_stored_submit",
                    checked_urls=check_urls,
                    scope_note="stored output may be transformed; browser execution used as fallback evidence",
                    cleanup_marker=cleanup_marker,
                    side_effect_possible=True,
                    stored_xss_submission_warning=STORED_XSS_SUBMISSION_WARNING,
                ),
            )
        return None

    # ------------------------------------------------------------------ #
    #  WAF bypass                                                          #
    # ------------------------------------------------------------------ #

    def _find_waf_bypass(self, target: dict, params: dict, param: str, context: str | None, headers: dict, cookies: dict, body_format: str) -> str | None:
        url = target["url"]
        method = target.get("method", "GET").upper()
        for payload in WAF_BYPASS_PAYLOADS.get(context or "unknown", WAF_BYPASS_PAYLOADS["unknown"]):
            test_data = dict(params)
            test_data[param] = payload
            if method == "POST":
                inject_csrf(self.client, url, test_data, headers, cookies)
            try:
                resp = self._submit(method, url, test_data, body_format, headers, cookies)
                if resp.status_code == 429:
                    time.sleep(2)
                    if method == "POST":
                        inject_csrf(self.client, url, test_data, headers, cookies)
                    try:
                        resp = self._submit(method, url, test_data, body_format, headers, cookies)
                    except Exception:
                        continue
                    if resp.status_code == 429:
                        # Sustained rate limiting means the bypass loop should stop
                        # instead of sending more probes to the target.
                        break
                if not detect_waf(resp):
                    logger.info("WAF bypass candidate found (stored): %s [%s]", url, param)
                    return payload
            except Exception:
                continue
        return None

    # ------------------------------------------------------------------ #
    #  CSRF                                                                #
    # ------------------------------------------------------------------ #


    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _submit(self, method: str, url: str, data: dict, body_format: str, headers: dict, cookies: dict):
        if method == "GET":
            return self._get_with_params(url, data, headers, cookies)
        return self._post(url, data, body_format, headers, cookies)

    def _post(self, url: str, data: dict, body_format: str, headers: dict, cookies: dict):
        if body_format == "json":
            return self.client.post(url, json=data, headers=headers, cookies=cookies)
        return self.client.post(url, data=data, headers=headers, cookies=cookies)

    def _get_with_params(self, url: str, data: dict, headers: dict, cookies: dict):
        parsed = urlparse(url)
        existing = {k: v[0] if v else "" for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        existing.update(data)
        new_url = urlunparse(parsed._replace(query=urlencode(existing)))
        return self.client.get(new_url, headers=headers, cookies=cookies)

    def _check_special_encoding(self, target: dict, params: dict, param: str, check_urls: list[str], marker: str) -> bool:
        data = dict(params)
        data[param] = f"{marker}{SPECIAL_PROBE}"
        method = target.get("method", "GET").upper()
        body_format = target.get("body_format", "form")
        headers = target.get("headers") or {}
        cookies = target.get("cookies") or {}
        if method == "POST":
            inject_csrf(self.client, target["url"], data, headers, cookies)
        try:
            self._submit(method, target["url"], data, body_format, headers, cookies)
            for url in check_urls:
                resp = self.client.get(url, headers=headers, cookies=cookies)
                analysis = self.analyzer.analyze(resp.text, marker, probe=SPECIAL_PROBE)
                if analysis.reflected:
                    return bool(analysis.escaped)
        except Exception:
            pass
        return True

    def _check_urls(self, target: dict, post_final_url: str) -> list[str]:
        urls = []
        for u in target.get("check_urls") or []:
            if u not in urls:
                urls.append(u)
        for u in [post_final_url, target["url"], *self.known_get_urls]:
            if u and u not in urls:
                urls.append(u)
        expanded = self._expand_candidate_links(urls, target)
        for u in expanded:
            if u not in urls:
                urls.append(u)
        return urls[:100]

    def _expand_candidate_links(self, base_urls: list[str], target: dict) -> list[str]:
        """Expand verification candidates by crawling first-level internal links.

        Stored workflows often render user content on detail pages linked from a
        list page. This keeps behavior generic without requiring schema changes.
        """
        results: list[str] = []
        submit_url = target.get("url", "")
        submit_host = urlparse(submit_url).netloc
        headers = target.get("headers") or {}
        cookies = target.get("cookies") or {}

        href_re = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        view_signals = ("view", "detail", "read", "show", "mtm_", "qna", "inquiry", "idx=")

        for base in base_urls[:10]:
            try:
                resp = self.client.get(base, headers=headers, cookies=cookies)
            except Exception:
                continue
            html = resp.text or ""
            for href in href_re.findall(html):
                abs_url = urljoin(base, href)
                parsed = urlparse(abs_url)
                if not parsed.scheme.startswith("http"):
                    continue
                if submit_host and parsed.netloc != submit_host:
                    continue
                if not any(sig in abs_url.lower() for sig in view_signals):
                    continue
                if abs_url not in results:
                    results.append(abs_url)
                if len(results) >= 30:
                    return results
        return results

    def _browser_verify_stored(
        self, 
        check_urls: list[str], 
        headers: dict, 
        cookies: dict,
        expected_marker: str | None = None,
        expected_alert_number: int | None = None
    ) -> tuple[bool, str | None, str | None]:
        if not check_urls:
            return False, None, None
        try:
            with self.browser_engine.launch() as browser:
                for check_url in check_urls[:20]:
                    try:
                        with self.browser_engine.context(
                            browser,
                            url=check_url,
                            headers=headers,
                            cookies=cookies,
                        ) as ctx:
                            page = ctx.new_page()
                            self.browser_engine.install_alert_capture(page)
                            page.goto(check_url, wait_until="domcontentloaded", timeout=self.browser_engine.timeout_ms)
                            self.browser_engine.wait_for_alert_capture(page, timeout_ms=1500)
                            triggered, alert_text = self.browser_engine.read_alert_capture(page)
                            if triggered:
                                # Verify that the alert matches the expected marker and alert number
                                if expected_marker and expected_alert_number:
                                    page_content = page.content()
                                    # Check if expected marker is in page content
                                    if expected_marker not in page_content:
                                        logger.debug(
                                            "[stored_xss] alert triggered (alert_text=%s) but expected_marker '%s' not in page; skipping (likely previous test data)",
                                            alert_text, expected_marker[:20]
                                        )
                                        continue
                                    # Check if alert_text matches expected alert number
                                    if alert_text and str(expected_alert_number) not in alert_text:
                                        logger.debug(
                                            "[stored_xss] alert triggered with unexpected value '%s' (expected %s); skipping",
                                            alert_text, expected_alert_number
                                        )
                                        continue
                                return True, check_url, alert_text
                    except Exception:
                        continue
        except Exception:
            return False, None, None
        return False, None, None

    def _analyze_relaxed(self, response_text: str, marker: str):
        """Analyze marker reflection with a safe fallback for transformed output.

        Some targets normalize/truncate stored values in list pages. We first use
        strict full-marker detection; if that fails, we accept a reflection when
        a sufficiently long unique marker prefix is present.
        """
        strict = self.analyzer.analyze(response_text, marker)
        if strict.reflected:
            return strict

        # 12+ chars keeps collision risk negligible while tolerating truncation.
        fallback = marker[:12]
        if len(fallback) >= 12:
            return self.analyzer.analyze(response_text, fallback)
        return strict

    def _candidate_params(self, target: dict, params: dict) -> list[str]:
        requested = [p for p in target.get("attack_params") or [] if p in params]
        if requested:
            return requested
        names = [n for n in params.keys() if n.lower() in HIGH_VALUE_PARAM_NAMES]
        return names or list(params.keys())[:2]
