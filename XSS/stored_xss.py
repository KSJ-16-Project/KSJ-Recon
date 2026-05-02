"""
Stored XSS 스캐너

1. POST 방식: requests로 페이로드 저장 → URL 순회 → 마커 탐색
2. DOM 방식:  Playwright로 폼 입력 → submit → 페이지 재방문 → alert 감지
             (localStorage 기반 DOM Stored XSS 대응)
"""

import requests
import logging
from typing import Optional
from urllib.parse import urlparse

from payloads import MARKER, PAYLOADS, WAF_INDICATORS
from context_analyzer import ContextAnalyzer
from result_builder import ResultBuilder

logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}
TIMEOUT = 10


class StoredXSSScanner:
    def __init__(self, urls: list, auth: dict = None):
        self.urls = urls
        self.context_analyzer = ContextAnalyzer()
        self.result_builder = ResultBuilder()
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        auth = auth or {}
        self.auth_cookies = {"session_id": auth["session_id"]} if auth.get("session_id") else {}
        self.auth_headers = {"Authorization": f"Bearer {auth['token']}"} if auth.get("token") else {}
        self.errors = []

        # 전체 URL 목록 (마커 탐색용)
        self.all_urls = [item.get("url") for item in urls if item.get("url")]

    def _is_auth_failed(self, response) -> bool:
        if response.status_code in [401, 403]:
            return True
        url_lower = response.url.lower()
        return "login" in url_lower or "signin" in url_lower

    def scan(self) -> list:
        """POST URL 대상 Stored XSS 스캔"""
        candidates = []

        post_urls = [
            item for item in self.urls
            if item.get("method", "GET").upper() == "POST"
        ]

        if not post_urls:
            logger.info("POST URL 없음, Stored XSS 스캔 스킵")
            return []

        for url_item in post_urls:
            results = self._scan_stored(url_item)
            candidates.extend(results)

        return candidates

    def _scan_stored(self, url_item: dict) -> list:
        """단일 POST URL에 대한 Stored XSS 스캔"""
        url = url_item.get("url", "")
        params = url_item.get("params", {})
        cookies = {**self.auth_cookies, **url_item.get("cookies", {})}
        headers = {**self.auth_headers, **url_item.get("headers", {})}

        if not url or not params:
            return []

        results = []

        for param_name in params:
            result = self._test_stored_param(
                url, param_name, params, cookies, headers
            )
            if result:
                results.append(result)

        return results

    def _test_stored_param(
        self,
        url: str,
        param_name: str,
        params: dict,
        cookies: dict,
        headers: dict
    ) -> Optional[dict]:
        """파라미터에 마커 저장 후 전체 URL 순회하며 탐색"""

        # 마커 삽입 후 POST
        test_data = params.copy()
        test_data[param_name] = MARKER

        try:
            response = self.session.post(
                url,
                data=test_data,
                cookies=cookies,
                headers=headers,
                timeout=TIMEOUT,
                verify=False
            )
            logger.debug(f"Stored 페이로드 저장 시도: {url} [{param_name}]")
        except (requests.ConnectionError, requests.Timeout) as e:
            logger.warning(f"네트워크 오류: {url} - {e}")
            self.errors.append(self.result_builder.build_error(
                url=url, method="POST", error="network_error", detail=str(e)
            ))
            return None
        except requests.RequestException as e:
            logger.warning(f"POST 요청 실패: {url} - {e}")
            self.errors.append(self.result_builder.build_error(
                url=url, method="POST", error="network_error", detail=str(e)
            ))
            return None

        # 세션 만료 / 인증 실패 감지
        if self._is_auth_failed(response):
            logger.warning(f"인증 실패 (스킵): {url} [{response.status_code}]")
            self.errors.append(self.result_builder.build_error(
                url=url, method="POST", error="auth_failed",
                detail=f"status={response.status_code} final_url={response.url}"
            ))
            return None

        # WAF 감지
        waf_detected = self._detect_waf(response)

        # 전체 URL 순회하며 마커 탐색
        found_url, context, evidence = self._find_marker_in_urls(cookies, headers)

        if not found_url:
            logger.debug(f"마커 미발견: {url} [{param_name}]")
            return None

        # 특수문자 인코딩 여부 확인
        special_chars_escaped = self._check_encoding_stored(
            url, param_name, params, cookies, headers
        )

        payload = PAYLOADS.get(context, PAYLOADS["html_body"])[0]

        logger.info(
            f"Stored XSS 후보 발견: {url} [{param_name}] "
            f"→ 출력 페이지: {found_url}"
        )

        return self.result_builder.build_finding(
            url=found_url,          # 마커가 출력되는 페이지
            method="POST",
            param=param_name,
            xss_type="stored",
            marker_reflected=True,
            context=context,
            special_chars_escaped=special_chars_escaped,
            payload_tried=payload,
            browser_verified=False,
            waf_detected=waf_detected,
            evidence=f"저장 URL: {url} → 출력 URL: {found_url}\n{evidence}"
        )

    def _find_marker_in_urls(
        self, cookies: dict, headers: dict
    ) -> tuple:
        """전체 URL 순회하며 마커가 반사되는 페이지 탐색"""
        for check_url in self.all_urls:
            try:
                response = self.session.get(
                    check_url,
                    cookies=cookies,
                    headers=headers,
                    timeout=TIMEOUT,
                    verify=False
                )
                if MARKER in response.text:
                    context = self.context_analyzer.analyze(
                        response.text, MARKER
                    )
                    evidence = self._extract_evidence(response.text)
                    return check_url, context, evidence
            except requests.RequestException:
                continue

        return None, None, ""

    def _check_encoding_stored(
        self, url, param_name, params, cookies, headers
    ) -> bool:
        """특수문자 인코딩 확인 (POST)"""
        test_data = params.copy()
        test_data[param_name] = "<\"'>"

        try:
            self.session.post(
                url,
                data=test_data,
                cookies=cookies,
                headers=headers,
                timeout=TIMEOUT,
                verify=False
            )
            # 저장 후 전체 URL 순회
            for check_url in self.all_urls:
                try:
                    response = self.session.get(
                        check_url,
                        cookies=cookies,
                        headers=headers,
                        timeout=TIMEOUT,
                        verify=False
                    )
                    if "<\"'>" in response.text:
                        return False
                except:
                    continue
        except:
            pass
        return True

    def _detect_waf(self, response) -> bool:
        if response.status_code in [403, 406, 429]:
            return True
        response_lower = response.text.lower()
        return any(
            indicator in response_lower for indicator in WAF_INDICATORS
        )

    def _extract_evidence(self, response_text: str) -> str:
        idx = response_text.find(MARKER)
        if idx == -1:
            return ""
        start = max(0, idx - 50)
        end = min(len(response_text), idx + len(MARKER) + 50)
        return f"...{response_text[start:end]}..."

    # ------------------------------------------------------------------ #
    #  DOM Stored XSS (Playwright 폼 조작)                                #
    # ------------------------------------------------------------------ #

    def scan_dom(self) -> list:
        """Playwright 폼 조작으로 DOM Stored XSS 탐지 (type=form URL만 대상)"""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            logger.warning("Playwright 없음 - DOM Stored XSS 스캔 스킵")
            return []

        form_urls = [item for item in self.urls if item.get("type") == "form"]
        if not form_urls:
            logger.info("type=form URL 없음, DOM Stored XSS 스캔 스킵")
            return []

        candidates = []
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                for url_item in form_urls:
                    result = self._scan_dom_url(browser, url_item)
                    if result:
                        candidates.append(result)
                browser.close()
        except Exception as e:
            logger.error(f"DOM Stored XSS 스캔 오류: {e}")

        logger.info(f"DOM Stored XSS 후보: {len(candidates)}개")
        return candidates

    def _scan_dom_url(self, browser, url_item: dict) -> Optional[dict]:
        """단일 URL에 폼 조작 시도, 성공한 첫 페이로드 결과 반환"""
        url = url_item.get("url", "")
        if not url:
            return None

        for payload in PAYLOADS["html_body"]:
            result = self._try_dom_payload(browser, url, payload, url_item)
            if result:
                return result
        return None

    def _try_dom_payload(
        self, browser, url: str, payload: str, url_item: dict
    ) -> Optional[dict]:
        """페이로드 입력 → submit → 재방문 → alert 감지"""
        ctx = browser.new_context()

        # 쿠키 주입 (auth_cookies + url별 cookies)
        merged_cookies = {**self.auth_cookies, **url_item.get("cookies", {})}
        if merged_cookies:
            domain = urlparse(url).netloc
            ctx.add_cookies([
                {"name": k, "value": v, "domain": domain, "path": "/"}
                for k, v in merged_cookies.items()
            ])

        # Authorization 헤더 주입
        merged_headers = {**self.auth_headers, **url_item.get("headers", {})}
        if merged_headers:
            ctx.set_extra_http_headers(merged_headers)

        page = ctx.new_page()
        alert_fired = False

        def handle_dialog(dialog):
            nonlocal alert_fired
            alert_fired = True
            dialog.accept()

        page.on("dialog", handle_dialog)

        try:
            # 1. 페이지 접속
            page.goto(url, timeout=10000, wait_until="domcontentloaded")
            page.wait_for_timeout(500)

            # 2. 입력 필드 탐색
            input_field = None
            param_name = "form_input"
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

            # 3. 페이로드 입력
            input_field.fill(payload)

            # 4. submit 버튼 클릭
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

            # 5. 페이지 재방문 (localStorage 에 저장된 페이로드 실행 유도)
            page.goto(url, timeout=10000, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)

            # 6. alert 감지
            if alert_fired:
                logger.info(f"DOM Stored XSS 확정: {url} [{param_name}]")
                return self.result_builder.build_finding(
                    url=url,
                    method="DOM",
                    param=param_name,
                    xss_type="stored_dom",
                    marker_reflected=True,
                    context="html_body",
                    special_chars_escaped=False,
                    payload_tried=payload,
                    browser_verified=True,
                    evidence="폼 입력 후 페이지 재방문 시 alert 실행 (localStorage 기반 추정)",
                )

        except Exception as e:
            logger.debug(f"DOM Stored XSS 시도 오류: {url} - {e}")
        finally:
            ctx.close()

        return None
