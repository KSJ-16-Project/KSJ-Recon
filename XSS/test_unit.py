"""
유닛 테스트
네트워크 없이 로직만 테스트

실행 방법:
    python tests/test_unit.py
"""

import sys
import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent))

from context_analyzer import ContextAnalyzer
from result_builder import ResultBuilder
from payloads import MARKER


class TestContextAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = ContextAnalyzer()

    def test_html_body_context(self):
        """HTML 본문 컨텍스트 감지"""
        html = f"<div>검색결과: {MARKER}</div>"
        result = self.analyzer.analyze(html, MARKER)
        self.assertEqual(result, "html_body")
        print(f"  ✅ html_body 감지: {result}")

    def test_html_attr_context(self):
        """HTML 속성 컨텍스트 감지"""
        html = f'<input type="text" value="{MARKER}">'
        result = self.analyzer.analyze(html, MARKER)
        self.assertEqual(result, "html_attr")
        print(f"  ✅ html_attr 감지: {result}")

    def test_js_string_context(self):
        """JS 문자열 컨텍스트 감지"""
        html = f"<script>var x = '{MARKER}';</script>"
        result = self.analyzer.analyze(html, MARKER)
        self.assertEqual(result, "js_string")
        print(f"  ✅ js_string 감지: {result}")

    def test_no_reflection(self):
        """마커 미반사 시 None 반환"""
        html = "<div>아무것도 없음</div>"
        result = self.analyzer.analyze(html, MARKER)
        self.assertIsNone(result)
        print(f"  ✅ 미반사 감지: {result}")

    def test_special_chars_not_escaped(self):
        """특수문자 미인코딩 감지"""
        html = "<div><script>alert</script></div>"
        result = self.analyzer.check_special_chars_escaped(html, ["<", ">"])
        self.assertFalse(result)
        print(f"  ✅ 특수문자 미인코딩 감지: escaped={result}")

    def test_special_chars_escaped(self):
        """특수문자 인코딩 감지"""
        # 마커와 함께 인코딩된 특수문자가 있는 경우
        html = f"<div>{MARKER} &lt;script&gt;alert&lt;/script&gt;</div>"
        result = self.analyzer.check_special_chars_escaped(html, ["<", ">"])
        self.assertTrue(result)
        print(f"  ✅ 특수문자 인코딩 감지: escaped={result}")


class TestResultBuilder(unittest.TestCase):
    def setUp(self):
        self.builder = ResultBuilder()

    def test_risk_level_high(self):
        """브라우저 검증 시 HIGH"""
        finding = self.builder.build_finding(
            url="http://test.com",
            method="GET",
            param="q",
            xss_type="reflected",
            marker_reflected=True,
            context="html_body",
            special_chars_escaped=False,
            payload_tried="<script>alert(1)</script>",
            browser_verified=True
        )
        self.assertEqual(finding["risk_level"], "high")
        print(f"  ✅ HIGH 위험도 판정: browser_verified=True → {finding['risk_level']}")

    def test_risk_level_medium(self):
        """반사 + 미인코딩 시 MEDIUM"""
        finding = self.builder.build_finding(
            url="http://test.com",
            method="GET",
            param="q",
            xss_type="reflected",
            marker_reflected=True,
            context="html_body",
            special_chars_escaped=False,
            payload_tried="<script>alert(1)</script>",
            browser_verified=False
        )
        self.assertEqual(finding["risk_level"], "medium")
        print(f"  ✅ MEDIUM 위험도 판정: reflected+not_escaped → {finding['risk_level']}")

    def test_risk_level_low(self):
        """반사됐지만 인코딩 시 LOW"""
        finding = self.builder.build_finding(
            url="http://test.com",
            method="GET",
            param="q",
            xss_type="reflected",
            marker_reflected=True,
            context="html_body",
            special_chars_escaped=True,
            payload_tried="<script>alert(1)</script>",
            browser_verified=False
        )
        self.assertEqual(finding["risk_level"], "low")
        print(f"  ✅ LOW 위험도 판정: escaped=True → {finding['risk_level']}")

    def test_build_summary(self):
        """요약 결과 빌드"""
        results = [
            {"risk_level": "high", "waf_detected": False},
            {"risk_level": "medium", "waf_detected": False},
            {"risk_level": "low", "waf_detected": True},
        ]
        output = self.builder.build(results, total_tested=10, base_url="http://test.com")
        self.assertEqual(output["summary"]["high"], 1)
        self.assertEqual(output["summary"]["medium"], 1)
        self.assertEqual(output["summary"]["low"], 1)
        self.assertTrue(output["summary"]["waf_detected"])
        print(f"  ✅ 요약 빌드: {output['summary']}")


class TestMissingFields(unittest.TestCase):
    """optional 필드 누락 처리 테스트"""

    def test_missing_cookies_and_headers(self):
        """cookies, headers 없어도 동작"""
        url_item = {
            "url": "http://test.com/search",
            "method": "GET",
            "params": {"q": "test"}
            # cookies, headers 없음
        }
        cookies = url_item.get("cookies", {})
        headers = url_item.get("headers", {})
        method = url_item.get("method", "GET")

        self.assertEqual(cookies, {})
        self.assertEqual(headers, {})
        self.assertEqual(method, "GET")
        print(f"  ✅ 누락 필드 기본값 처리: cookies={cookies}, headers={headers}")

    def test_missing_params(self):
        """params 없어도 URL에서 파싱"""
        from urllib.parse import urlparse, parse_qs
        url = "http://test.com/search?q=test&page=1"
        url_item = {
            "url": url,
            "method": "GET"
            # params 없음
        }
        params = url_item.get("params", {})
        if not params:
            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        self.assertIn("q", params)
        self.assertIn("page", params)
        print(f"  ✅ URL에서 파라미터 파싱: {params}")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("XSS 모듈 유닛 테스트")
    print("="*60)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestContextAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestResultBuilder))
    suite.addTests(loader.loadTestsFromTestCase(TestMissingFields))

    runner = unittest.TextTestRunner(verbosity=0)
    runner.run(suite)
