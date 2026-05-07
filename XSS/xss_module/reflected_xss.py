"""Reflected XSS candidate detector.

Covers:
- GET parameter reflection
- POST parameter reflection (form-encoded and JSON body)
- HTTP header reflection (Referer, User-Agent, X-Forwarded-For, X-Forwarded-Host)
"""

from __future__ import annotations

import logging
import time
from urllib.parse import urlparse, parse_qs, urlunparse

from .context_analyzer import ContextAnalyzer
from .csrf import extract_csrf
from .http_client import HttpClient
from .payloads import (
    CONTEXT_PAYLOADS, HIGH_VALUE_PARAM_NAMES, SPECIAL_PROBE,
    WAF_BYPASS_PAYLOADS, WAF_INDICATORS, new_marker,
)
from .result_builder import ResultBuilder

logger = logging.getLogger(__name__)

INJECTABLE_HEADERS = ["Referer", "User-Agent", "X-Forwarded-For", "X-Forwarded-Host"]


class ReflectedXSSScanner:
    def __init__(self, targets: list[dict], client: HttpClient, builder: ResultBuilder, auth_refresher=None):
        self.targets = targets
        self.client = client
        self.builder = builder
        self.auth_refresher = auth_refresher
        self.analyzer = ContextAnalyzer()
        self.errors: list[dict] = []

    def scan(self) -> list[dict]:
        findings: list[dict] = []
        total = len(self.targets)
        for i, target in enumerate(self.targets):
            method = target.get("method", "GET").upper()
            params = target.get("params") or self._params_from_url(target["url"])
            if not params:
                continue
            logger.info("[%d/%d] reflected scan: %s", i + 1, total, target["url"])
            for param in self._prioritized_params(params):
                if method == "GET":
                    finding = self._test_param(target, params, param)
                elif method == "POST":
                    finding = self._test_post_param(target, params, param)
                else:
                    finding = None
                if finding:
                    findings.append(finding)
        return findings

    def scan_headers(self) -> list[dict]:
        """Test HTTP header injection and check if the value is reflected."""
        findings: list[dict] = []
        seen: set[str] = set()
        for target in self.targets:
            url = target.get("url", "")
            if not url or url in seen:
                continue
            seen.add(url)
            for header_name in INJECTABLE_HEADERS:
                finding = self._test_header(target, header_name)
                if finding:
                    findings.append(finding)
        return findings

    # ------------------------------------------------------------------ #
    #  GET param                                                           #
    # ------------------------------------------------------------------ #

    def _test_param(self, target: dict, params: dict, param: str) -> dict | None:
        url = target["url"]
        marker = new_marker()
        test_params = dict(params)
        test_params[param] = marker
        headers = target.get("headers") or {}
        cookies = target.get("cookies") or {}
        base_url = self._strip_query(url)

        try:
            resp = self.client.get(base_url, params=test_params, headers=headers, cookies=cookies)
        except Exception as e:
            self.errors.append(self.builder.error(url=url, phase="reflected_marker", error="request_failed", detail=str(e), category="network_error"))
            return None

        # 429 retry: WAF rate-limit → wait 2 s then retry once
        if resp.status_code == 429:
            logger.warning("429 rate-limit on %s [%s] – retrying after 2s", url, param)
            time.sleep(2)
            try:
                resp = self.client.get(base_url, params=test_params, headers=headers, cookies=cookies)
            except Exception as e:
                self.errors.append(self.builder.error(url=url, phase="reflected_marker", error="request_failed", detail=str(e), category="network_error"))
                return None
            if resp.status_code == 429:
                self.errors.append(self.builder.error(url=url, phase="reflected_marker", error="waf_rate_limited", detail="429 after retry", category="waf_block"))
                return None

        if self._auth_failed(resp):
            if self.auth_refresher:
                self.auth_refresher()
                try:
                    resp = self.client.get(base_url, params=test_params, headers=headers, cookies=cookies)
                except Exception as e:
                    self.errors.append(self.builder.error(url=url, phase="reflected_marker_retry", error="request_failed", detail=str(e), category="network_error"))
                    return None
            if self._auth_failed(resp):
                self.errors.append(self.builder.error(url=url, phase="reflected_marker", error="auth_failed", detail=f"status={resp.status_code}", category="auth_failed"))
                return None

        analysis = self.analyzer.analyze(resp.text, marker)
        if not analysis.reflected:
            return None

        escaped = self._check_special_encoding(target, params, param, marker)
        analysis.escaped = escaped
        payload = self._select_payload(analysis.context)
        risk, should_verify = self._risk_and_verify(analysis.context, escaped)
        waf = self._detect_waf(resp)

        bypass_payload = None
        if waf and not escaped:
            bypass_payload = self._find_waf_bypass_get(target, params, param, analysis.context, headers, cookies)

        return self.builder.finding(
            type="reflected_xss_candidate",
            url=url,
            method="GET",
            param=param,
            source=target.get("source", "input"),
            marker=marker,
            reflected=True,
            context=analysis.context,
            escaped=escaped,
            quote=analysis.quote,
            quote_breakout_possible=analysis.quote_breakout_possible,
            payload=payload,
            browser_verified=False,
            browser_verification_required=should_verify,
            verification_status="skipped",
            risk=risk,
            waf_detected=waf,
            waf_bypass_possible=bypass_payload is not None,
            waf_bypass_payload=bypass_payload,
            evidence={
                "request_url": resp.url,
                "status_code": resp.status_code,
                "snippet": analysis.snippet,
                "reason": analysis.reason,
            },
        )

    # ------------------------------------------------------------------ #
    #  POST param (form-encoded or JSON body)                             #
    # ------------------------------------------------------------------ #

    def _test_post_param(self, target: dict, params: dict, param: str) -> dict | None:
        url = target["url"]
        marker = new_marker()
        test_data = dict(params)
        test_data[param] = marker
        headers = target.get("headers") or {}
        cookies = target.get("cookies") or {}
        body_format = target.get("body_format", "form")

        self._inject_csrf(url, test_data, headers, cookies, body_format)

        try:
            resp = self._post(url, test_data, body_format, headers, cookies)
        except Exception as e:
            self.errors.append(self.builder.error(url=url, phase="reflected_post_marker", error="request_failed", detail=str(e), category="network_error"))
            return None

        # 429 retry
        if resp.status_code == 429:
            logger.warning("429 rate-limit on %s [%s] – retrying after 2s", url, param)
            time.sleep(2)
            self._inject_csrf(url, test_data, headers, cookies, body_format)
            try:
                resp = self._post(url, test_data, body_format, headers, cookies)
            except Exception as e:
                self.errors.append(self.builder.error(url=url, phase="reflected_post_marker", error="request_failed", detail=str(e), category="network_error"))
                return None
            if resp.status_code == 429:
                self.errors.append(self.builder.error(url=url, phase="reflected_post_marker", error="waf_rate_limited", detail="429 after retry", category="waf_block"))
                return None

        if self._auth_failed(resp):
            if self.auth_refresher:
                self.auth_refresher()
                self._inject_csrf(url, test_data, headers, cookies, body_format)
                try:
                    resp = self._post(url, test_data, body_format, headers, cookies)
                except Exception as e:
                    self.errors.append(self.builder.error(url=url, phase="reflected_post_marker_retry", error="request_failed", detail=str(e), category="network_error"))
                    return None
            if self._auth_failed(resp):
                self.errors.append(self.builder.error(url=url, phase="reflected_post_marker", error="auth_failed", detail=f"status={resp.status_code}", category="auth_failed"))
                return None

        analysis = self.analyzer.analyze(resp.text, marker)
        if not analysis.reflected:
            return None

        escaped = self._check_special_encoding(target, params, param, marker)
        analysis.escaped = escaped
        payload = self._select_payload(analysis.context)
        # POST XSS uses the same risk/verify logic as GET (4-1 fix)
        risk, should_verify = self._risk_and_verify(analysis.context, escaped)
        waf = self._detect_waf(resp)

        bypass_payload = None
        if waf and not escaped:
            bypass_payload = self._find_waf_bypass_post(target, params, param, analysis.context, headers, cookies, body_format)

        return self.builder.finding(
            type="reflected_xss_post_candidate",
            url=url,
            method="POST",
            param=param,
            source=target.get("source", "input"),
            marker=marker,
            reflected=True,
            context=analysis.context,
            escaped=escaped,
            quote=analysis.quote,
            quote_breakout_possible=analysis.quote_breakout_possible,
            payload=payload,
            browser_verified=False,
            browser_verification_required=should_verify,
            verification_status="skipped",
            risk=risk,
            waf_detected=waf,
            waf_bypass_possible=bypass_payload is not None,
            waf_bypass_payload=bypass_payload,
            body_format=body_format,
            # Browser verification must be able to rebuild the original POST body
            # and replace only the vulnerable parameter with the executable payload.
            body_params=dict(params),
            evidence={
                "request_url": url,
                "status_code": resp.status_code,
                "snippet": analysis.snippet,
                "reason": analysis.reason,
            },
        )

    # ------------------------------------------------------------------ #
    #  HTTP header injection                                               #
    # ------------------------------------------------------------------ #

    def _test_header(self, target: dict, header_name: str) -> dict | None:
        url = target["url"]
        marker = new_marker()
        inject_headers = dict(target.get("headers") or {})
        inject_headers[header_name] = marker
        cookies = target.get("cookies") or {}

        try:
            resp = self.client.get(url, headers=inject_headers, cookies=cookies)
        except Exception as e:
            self.errors.append(self.builder.error(url=url, phase="header_reflection", error="request_failed", detail=str(e), category="network_error"))
            return None

        analysis = self.analyzer.analyze(resp.text, marker)
        if not analysis.reflected:
            return None

        payload = self._select_payload(analysis.context)
        risk, should_verify = self._risk_and_verify(analysis.context, escaped=False)
        waf = self._detect_waf(resp)

        logger.info("header reflection: %s [%s] context=%s", url, header_name, analysis.context)
        return self.builder.finding(
            type="header_reflected_xss_candidate",
            url=url,
            method="GET",
            param=header_name,
            source="header",
            marker=marker,
            reflected=True,
            context=analysis.context,
            escaped=False,
            payload=payload,
            browser_verified=False,
            browser_verification_required=should_verify,
            verification_status="skipped",
            risk=risk,
            waf_detected=waf,
            evidence={
                "request_url": resp.url,
                "status_code": resp.status_code,
                "snippet": analysis.snippet,
                "reason": f"marker injected via {header_name} header reflected in response",
            },
        )

    # ------------------------------------------------------------------ #
    #  WAF bypass                                                          #
    # ------------------------------------------------------------------ #

    def _find_waf_bypass_get(self, target: dict, params: dict, param: str, context: str | None, headers: dict, cookies: dict) -> str | None:
        url = self._strip_query(target["url"])
        for payload in WAF_BYPASS_PAYLOADS.get(context or "unknown", WAF_BYPASS_PAYLOADS["unknown"]):
            test_params = dict(params)
            test_params[param] = payload
            try:
                resp = self.client.get(url, params=test_params, headers=headers, cookies=cookies)
                if resp.status_code == 429:
                    time.sleep(2)
                    try:
                        resp = self.client.get(url, params=test_params, headers=headers, cookies=cookies)
                    except Exception:
                        continue
                    if resp.status_code == 429:
                        # 429가 재시도 후에도 유지되면 rate limit이 지속되는 상태이므로
                        # 추가 bypass 탐색을 중단해 대상 서버에 불필요한 요청을 보내지 않는다.
                        break
                if not self._detect_waf(resp):
                    logger.info("WAF bypass candidate found (GET): %s [%s]", url, param)
                    return payload
            except Exception:
                continue
        return None

    def _find_waf_bypass_post(self, target: dict, params: dict, param: str, context: str | None, headers: dict, cookies: dict, body_format: str) -> str | None:
        url = target["url"]
        for payload in WAF_BYPASS_PAYLOADS.get(context or "unknown", WAF_BYPASS_PAYLOADS["unknown"]):
            test_data = dict(params)
            test_data[param] = payload
            self._inject_csrf(url, test_data, headers, cookies, body_format)
            try:
                resp = self._post(url, test_data, body_format, headers, cookies)
                if resp.status_code == 429:
                    time.sleep(2)
                    self._inject_csrf(url, test_data, headers, cookies, body_format)
                    try:
                        resp = self._post(url, test_data, body_format, headers, cookies)
                    except Exception:
                        continue
                    if resp.status_code == 429:
                        # 429가 재시도 후에도 유지되면 rate limit이 지속되는 상태이므로
                        # 추가 bypass 탐색을 중단해 대상 서버에 불필요한 요청을 보내지 않는다.
                        break
                if not self._detect_waf(resp):
                    logger.info("WAF bypass candidate found (POST): %s [%s]", url, param)
                    return payload
            except Exception:
                continue
        return None

    # ------------------------------------------------------------------ #
    #  CSRF                                                                #
    # ------------------------------------------------------------------ #

    def _inject_csrf(self, url: str, data: dict, headers: dict, cookies: dict, body_format: str) -> None:
        """Fetch a fresh CSRF token and inject it into data in-place."""
        try:
            resp = self.client.get(url, headers=headers, cookies=cookies)
            result = extract_csrf(resp.text)
            if result:
                field, token = result
                data[field] = token
                logger.debug("CSRF token injected: %s", field)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _post(self, url: str, data: dict, body_format: str, headers: dict, cookies: dict):
        if body_format == "json":
            return self.client.post(url, json=data, headers=headers, cookies=cookies)
        return self.client.post(url, data=data, headers=headers, cookies=cookies)

    def _check_special_encoding(self, target: dict, params: dict, param: str, marker: str) -> bool:
        probe = f"{marker}{SPECIAL_PROBE}"
        test_params = dict(params)
        test_params[param] = probe
        url = self._strip_query(target["url"])
        headers = target.get("headers") or {}
        cookies = target.get("cookies") or {}
        method = target.get("method", "GET").upper()
        body_format = target.get("body_format", "form")
        try:
            if method == "POST":
                self._inject_csrf(target["url"], test_params, headers, cookies, body_format)
                resp = self._post(url, test_params, body_format, headers, cookies)
            else:
                resp = self.client.get(url, params=test_params, headers=headers, cookies=cookies)
        except Exception:
            return True
        analysis = self.analyzer.analyze(resp.text, marker, probe=probe)
        return bool(analysis.escaped)

    def _risk_and_verify(self, context: str | None, escaped: bool) -> tuple[str, bool]:
        context = context or "unknown"
        if context.startswith("event_handler_js"):
            return "MEDIUM", True
        if context == "url_context":
            return "MEDIUM", True
        if escaped:
            return "LOW", False
        if context in {
            "html_attribute_double", "html_attribute_single", "html_attribute_unquoted",
            "js_string_double", "js_string_single", "js_block", "html_body", "html_comment",
        }:
            return "MEDIUM", True
        return "LOW", False

    def _select_payload(self, context: str | None) -> str:
        return CONTEXT_PAYLOADS.get(context or "unknown", CONTEXT_PAYLOADS["unknown"])[0]

    def _prioritized_params(self, params: dict) -> list[str]:
        names = list(params.keys())
        return sorted(names, key=lambda n: 0 if n.lower() in HIGH_VALUE_PARAM_NAMES else 1)

    def _params_from_url(self, url: str) -> dict:
        parsed = urlparse(url)
        return {k: v[0] if v else "" for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

    def _strip_query(self, url: str) -> str:
        parsed = urlparse(url)
        return urlunparse(parsed._replace(query=""))

    def _auth_failed(self, resp) -> bool:
        if resp.status_code in {401, 403}:
            return True
        final = resp.url.lower()
        return "login" in final or "signin" in final

    def _detect_waf(self, resp) -> bool:
        if resp.status_code in {403, 406, 429}:
            return True
        body = resp.text.lower()
        return any(ind in body for ind in WAF_INDICATORS)
