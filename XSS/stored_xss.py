"""
Stored XSS 스캐너
POST 요청으로 페이로드 저장 후
Crawler/Fuzzer URL 전체 순회하며 실행 여부 확인

흐름:
1. POST 파라미터에 마커 삽입 후 저장
2. 전체 URL 목록 순회
3. 마커가 반사되는 페이지 발견 → Stored XSS 후보
4. 브라우저 검증은 BrowserVerifier에서
"""

import requests
import logging
from typing import List, Optional

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
    def __init__(self, urls: list):
        self.urls = urls
        self.context_analyzer = ContextAnalyzer()
        self.result_builder = ResultBuilder()
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

        # 전체 URL 목록 (마커 탐색용)
        self.all_urls = [item.get("url") for item in urls if item.get("url")]

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
        cookies = url_item.get("cookies", {})
        headers = url_item.get("headers", {})

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
        except requests.RequestException as e:
            logger.warning(f"POST 요청 실패: {url} - {e}")
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
