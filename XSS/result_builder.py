"""
결과 빌더
XSS 탐지 결과를 보고서 LLM용 JSON으로 변환
"""

from datetime import datetime
from typing import List


class ResultBuilder:

    def build(self, results: list, total_tested: int, base_url: str) -> dict:
        high = [r for r in results if r.get("risk_level") == "high"]
        medium = [r for r in results if r.get("risk_level") == "medium"]
        low = [r for r in results if r.get("risk_level") == "low"]
        waf_detected = any(r.get("waf_detected") for r in results)

        return {
            "scan_info": {
                "base_url": base_url,
                "scan_time": datetime.now().isoformat(),
                "scanner": "XSS Module v1.0"
            },
            "xss_results": results,
            "summary": {
                "total_tested": total_tested,
                "total_found": len(results),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
                "waf_detected": waf_detected,
                "scope_excluded": [
                    "DOM XSS - JS 코드 흐름 분석 필요, 스코프 외",
                    "WAF 우회 - 감지만 수행"
                ]
            }
        }

    def build_finding(
        self,
        url: str,
        method: str,
        param: str,
        xss_type: str,
        marker_reflected: bool,
        context: str,
        special_chars_escaped: bool,
        payload_tried: str,
        browser_verified: bool,
        screenshot_alert: str = None,
        screenshot_after: str = None,
        waf_detected: bool = False,
        evidence: str = ""
    ) -> dict:
        """개별 XSS 탐지 결과 생성"""

        # risk_level 결정
        if browser_verified:
            risk_level = "high"
        elif marker_reflected and not special_chars_escaped:
            risk_level = "medium"
        else:
            risk_level = "low"

        result = {
            "url": url,
            "method": method,
            "param": param,
            "xss_type": xss_type,           # "reflected" or "stored"
            "risk_level": risk_level,
            "marker_reflected": marker_reflected,
            "context": context,              # html_body / html_attr / js_string / url_context
            "special_chars_escaped": special_chars_escaped,
            "payload_tried": payload_tried,
            "browser_verified": browser_verified,
            "waf_detected": waf_detected,
            "evidence": evidence,
        }

        if screenshot_alert:
            result["screenshot_alert"] = screenshot_alert
        if screenshot_after:
            result["screenshot_after"] = screenshot_after

        return result
