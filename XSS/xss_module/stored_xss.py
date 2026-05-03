"""Limited Stored XSS candidate detector.

This module intentionally only submits forms marked as safe_to_submit or forms
that look text-only and non-destructive. It checks whether a marker becomes
observable on configured check URLs or known crawled URLs.
"""

from __future__ import annotations

import logging

from .context_analyzer import ContextAnalyzer
from .csrf import extract_csrf
from .http_client import HttpClient
from .payloads import CONTEXT_PAYLOADS, HIGH_VALUE_PARAM_NAMES, SPECIAL_PROBE, WAF_BYPASS_PAYLOADS, WAF_INDICATORS, new_marker
from .result_builder import ResultBuilder

logger = logging.getLogger(__name__)


class StoredXSSScanner:
    def __init__(self, targets: list[dict], client: HttpClient, builder: ResultBuilder, auth_refresher=None):
        self.targets = targets
        self.client = client
        self.builder = builder
        self.auth_refresher = auth_refresher
        self.analyzer = ContextAnalyzer()
        self.errors: list[dict] = []
        self.known_get_urls = [t["url"] for t in targets if t.get("method", "GET").upper() == "GET"]

    def scan(self) -> list[dict]:
        findings: list[dict] = []
        for target in self.targets:
            if target.get("method", "GET").upper() != "POST":
                continue
            if not target.get("safe_to_submit"):
                continue
            params = target.get("params") or {}
            if not params:
                continue
            for param in self._candidate_params(params):
                finding = self._test_form(target, params, param)
                if finding:
                    findings.append(finding)
        return findings

    def _auth_failed(self, resp) -> bool:
        if resp.status_code in {401, 403}:
            return True
        return "login" in resp.url.lower() or "signin" in resp.url.lower()

    def _detect_waf(self, resp) -> bool:
        if resp.status_code in {403, 406, 429}:
            return True
        body = resp.text.lower()
        return any(ind in body for ind in WAF_INDICATORS)

    def _test_form(self, target: dict, params: dict, param: str) -> dict | None:
        marker = new_marker()
        data = dict(params)
        data[param] = marker
        url = target["url"]
        req_headers = target.get("headers") or {}
        req_cookies = target.get("cookies") or {}
        body_format = target.get("body_format", "form")

        self._inject_csrf(url, data, req_headers, req_cookies)

        try:
            post_resp = self._post(url, data, body_format, req_headers, req_cookies)
        except Exception as e:
            self.errors.append(self.builder.error(url=url, phase="stored_submit", error="request_failed", detail=str(e)))
            return None

        if self._auth_failed(post_resp):
            if self.auth_refresher:
                self.auth_refresher()
                self._inject_csrf(url, data, req_headers, req_cookies)
                try:
                    post_resp = self._post(url, data, body_format, req_headers, req_cookies)
                except Exception as e:
                    self.errors.append(self.builder.error(url=url, phase="stored_submit_retry", error="request_failed", detail=str(e)))
                    return None
            if self._auth_failed(post_resp):
                self.errors.append(self.builder.error(url=url, phase="stored_submit", error="auth_failed", detail=f"status={post_resp.status_code}"))
                return None

        waf = self._detect_waf(post_resp)

        check_urls = self._check_urls(target, post_resp.url)
        for check_url in check_urls:
            try:
                resp = self.client.get(check_url, headers=req_headers, cookies=req_cookies)
            except Exception:
                continue
            analysis = self.analyzer.analyze(resp.text, marker)
            if not analysis.reflected:
                continue

            escaped = self._check_special_encoding(target, params, param, check_urls, marker)
            payload = CONTEXT_PAYLOADS.get(analysis.context or "unknown", CONTEXT_PAYLOADS["unknown"])[0]
            risk = "LOW" if escaped else "MEDIUM"

            bypass_payload = None
            if waf and not escaped:
                bypass_payload = self._find_waf_bypass(target, params, param, analysis.context, req_headers, req_cookies, body_format)

            return self.builder.finding(
                type="stored_xss_candidate_limited",
                url=check_url,
                source_url=url,
                method="POST",
                param=param,
                marker=marker,
                reflected=True,
                context=analysis.context,
                escaped=escaped,
                payload=payload,
                browser_verified=False,
                browser_verification_required=False,
                waf_detected=waf,
                waf_bypass_possible=bypass_payload is not None,
                waf_bypass_payload=bypass_payload,
                risk=risk,
                evidence={
                    "submit_status": post_resp.status_code,
                    "checked_url": check_url,
                    "snippet": analysis.snippet,
                    "reason": "marker submitted through a safe POST form and later observed on a reachable page",
                    "scope_note": "limited stored XSS check; not a full stored-XSS workflow crawler",
                },
            )
        return None

    # ------------------------------------------------------------------ #
    #  WAF bypass                                                          #
    # ------------------------------------------------------------------ #

    def _find_waf_bypass(self, target: dict, params: dict, param: str, context: str | None, headers: dict, cookies: dict, body_format: str) -> str | None:
        url = target["url"]
        for payload in WAF_BYPASS_PAYLOADS.get(context or "unknown", WAF_BYPASS_PAYLOADS["unknown"]):
            test_data = dict(params)
            test_data[param] = payload
            self._inject_csrf(url, test_data, headers, cookies)
            try:
                resp = self._post(url, test_data, body_format, headers, cookies)
                if not self._detect_waf(resp):
                    logger.info("WAF bypass candidate found (stored): %s [%s]", url, param)
                    return payload
            except Exception:
                continue
        return None

    # ------------------------------------------------------------------ #
    #  CSRF                                                                #
    # ------------------------------------------------------------------ #

    def _inject_csrf(self, url: str, data: dict, headers: dict, cookies: dict) -> None:
        """Fetch a fresh CSRF token from the form page and inject into data in-place."""
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

    def _check_special_encoding(self, target: dict, params: dict, param: str, check_urls: list[str], marker: str) -> bool:
        data = dict(params)
        data[param] = f"{marker}{SPECIAL_PROBE}"
        body_format = target.get("body_format", "form")
        headers = target.get("headers") or {}
        cookies = target.get("cookies") or {}
        self._inject_csrf(target["url"], data, headers, cookies)
        try:
            self._post(target["url"], data, body_format, headers, cookies)
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
        return urls[:20]

    def _candidate_params(self, params: dict) -> list[str]:
        names = [n for n in params.keys() if n.lower() in HIGH_VALUE_PARAM_NAMES]
        return names or list(params.keys())[:2]
