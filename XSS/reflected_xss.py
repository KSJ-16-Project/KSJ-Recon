"""
Reflected XSS 스캐너
requests 기반으로 빠르게 후보 URL 필터링

단계:
1. 파라미터 추출
2. 마커 반사 확인
3. 컨텍스트 분류
4. 특수문자 인코딩 여부 확인
5. 후보 결과 반환 (브라우저 검증은 BrowserVerifier에서)
"""

import requests
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Optional

from payloads import MARKER, PAYLOADS, SPECIAL_CHARS, WAF_INDICATORS
from context_analyzer import ContextAnalyzer
from result_builder import ResultBuilder

logger = logging.getLogger(__name__)

# requests 기본 설정
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}
TIMEOUT = 10


class ReflectedXSSScanner:
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

    def _is_auth_failed(self, response) -> bool:
        if response.status_code in [401, 403]:
            return True
        url_lower = response.url.lower()
        return "login" in url_lower or "signin" in url_lower

    def scan(self) -> list:
        """전체 URL 스캔 후 후보 목록 반환"""
        candidates = []

        for url_item in self.urls:
            method = url_item.get("method", "GET").upper()
            
            # GET 요청만 Reflected XSS 대상
            # POST는 StoredXSSScanner에서 처리
            if method != "GET":
                continue

            results = self._scan_url(url_item)
            candidates.extend(results)

        return candidates

    def _scan_url(self, url_item: dict) -> list:
        """단일 URL에 대한 Reflected XSS 스캔"""
        url = url_item.get("url", "")
        params = url_item.get("params", {})
        cookies = {**self.auth_cookies, **url_item.get("cookies", {})}
        headers = {**self.auth_headers, **url_item.get("headers", {})}

        if not url:
            return []

        # URL에서 파라미터 추출 (params가 없으면 URL에서 파싱)
        if not params:
            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if not params:
            logger.debug(f"파라미터 없음, 스킵: {url}")
            return []

        results = []
        for param_name in params:
            result = self._test_param(
                url, param_name, params, cookies, headers
            )
            if result:
                results.append(result)

        return results

    def _test_param(
        self,
        url: str,
        param_name: str,
        params: dict,
        cookies: dict,
        headers: dict
    ) -> Optional[dict]:
        """단일 파라미터에 마커 삽입 후 반사 확인"""

        # 마커 삽입
        test_params = params.copy()
        test_params[param_name] = MARKER

        try:
            response = self.session.get(
                url,
                params=test_params,
                cookies=cookies,
                headers=headers,
                timeout=TIMEOUT,
                verify=False
            )
        except (requests.ConnectionError, requests.Timeout) as e:
            logger.warning(f"네트워크 오류: {url} - {e}")
            self.errors.append(self.result_builder.build_error(
                url=url, method="GET", error="network_error", detail=str(e)
            ))
            return None
        except requests.RequestException as e:
            logger.warning(f"요청 실패: {url} - {e}")
            self.errors.append(self.result_builder.build_error(
                url=url, method="GET", error="network_error", detail=str(e)
            ))
            return None

        # 세션 만료 / 인증 실패 감지
        if self._is_auth_failed(response):
            logger.warning(f"인증 실패 (스킵): {url} [{response.status_code}]")
            self.errors.append(self.result_builder.build_error(
                url=url, method="GET", error="auth_failed",
                detail=f"status={response.status_code} final_url={response.url}"
            ))
            return None

        response_text = response.text

        # WAF 감지
        waf_detected = self._detect_waf(response)

        # 마커 반사 확인
        marker_reflected = MARKER in response_text

        if not marker_reflected:
            logger.debug(f"마커 미반사: {url} [{param_name}]")
            return None

        # 컨텍스트 분류
        context = self.context_analyzer.analyze(response_text, MARKER)

        # 특수문자 인코딩 여부 확인
        # 마커 대신 특수문자 삽입해서 확인
        special_chars_escaped = self._check_encoding(
            url, param_name, params, cookies, headers
        )

        # 컨텍스트에 맞는 첫 번째 페이로드 선택
        payload = self._select_payload(context)

        # 증거 텍스트 추출
        evidence = self._extract_evidence(response_text)

        logger.info(
            f"Reflected XSS 후보 발견: {url} [{param_name}] "
            f"context={context} escaped={special_chars_escaped}"
        )

        return self.result_builder.build_finding(
            url=url,
            method="GET",
            param=param_name,
            xss_type="reflected",
            marker_reflected=True,
            context=context,
            special_chars_escaped=special_chars_escaped,
            payload_tried=payload,
            browser_verified=False,  # 브라우저 검증은 BrowserVerifier에서
            waf_detected=waf_detected,
            evidence=evidence
        )

    def _check_encoding(
        self, url, param_name, params, cookies, headers
    ) -> bool:
        """특수문자가 인코딩되는지 확인"""
        test_params = params.copy()
        test_params[param_name] = "<\"'>"

        try:
            response = self.session.get(
                url,
                params=test_params,
                cookies=cookies,
                headers=headers,
                timeout=TIMEOUT,
                verify=False
            )
            # 원본 특수문자가 그대로 있으면 인코딩 안 됨
            return not any(c in response.text for c in ["<", '"', "'", ">"])
        except:
            return True  # 확인 불가 시 안전하다고 가정

    def _detect_waf(self, response) -> bool:
        """WAF 감지"""
        if response.status_code in [403, 406, 429]:
            return True
        response_lower = response.text.lower()
        return any(indicator in response_lower for indicator in WAF_INDICATORS)

    def _select_payload(self, context: str) -> str:
        """컨텍스트에 맞는 페이로드 선택"""
        payload_list = PAYLOADS.get(context, PAYLOADS["html_body"])
        return payload_list[0]

    def _extract_evidence(self, response_text: str) -> str:
        """마커 주변 텍스트를 증거로 추출"""
        idx = response_text.find(MARKER)
        if idx == -1:
            return ""
        start = max(0, idx - 50)
        end = min(len(response_text), idx + len(MARKER) + 50)
        return f"...{response_text[start:end]}..."
