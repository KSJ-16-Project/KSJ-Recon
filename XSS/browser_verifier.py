"""
브라우저 검증기 (Playwright 기반)
requests 단계에서 걸러진 후보 URL에 대해
실제 브라우저로 XSS 실행 여부 확인

확인 방법:
- alert() 이벤트 캐치
- 스크린샷 캡처 (alert 뜬 순간 + 닫힌 후)
"""

import logging
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from payloads import PAYLOADS

logger = logging.getLogger(__name__)

BROWSER_TIMEOUT = 10000  # ms


class BrowserVerifier:
    def __init__(self, evidence_dir: Path):
        self.evidence_dir = evidence_dir

    def verify(self, candidates: list, on_result=None) -> list:
        """후보 목록 전체 브라우저 검증.
        on_result: 각 URL 검증 완료 시 호출되는 콜백 (Ctrl+C 부분 저장용)
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            logger.error("Playwright가 설치되지 않음.")
            return candidates

        results = []

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)

                for candidate in candidates:
                    verified = self._verify_single(browser, candidate)
                    results.append(verified)
                    if on_result:
                        on_result(verified)

                browser.close()
        except Exception as e:
            logger.error(f"브라우저 실행 실패: {e}")
            logger.warning("브라우저 검증 없이 후보 결과만 반환합니다.")
            return candidates

        return results

    def _verify_single(self, browser, candidate: dict) -> dict:
        """단일 후보 브라우저 검증"""
        url = candidate.get("url", "")
        param = candidate.get("param", "")
        context = candidate.get("context", "html_body")
        xss_type = candidate.get("xss_type", "reflected")
        cookies = {}  # candidate에서 추출 가능하면 추가

        # 컨텍스트에 맞는 페이로드 목록
        payload_list = PAYLOADS.get(context, PAYLOADS["html_body"])

        for payload in payload_list:
            verified, screenshot_alert, screenshot_after = self._try_payload(
                browser, url, param, payload, cookies, xss_type
            )

            if verified:
                logger.info(f"XSS 확정 (브라우저 실행 확인): {url} [{param}]")
                candidate["browser_verified"] = True
                candidate["risk_level"] = "high"
                candidate["payload_tried"] = payload
                if screenshot_alert:
                    candidate["screenshot_alert"] = str(screenshot_alert)
                if screenshot_after:
                    candidate["screenshot_after"] = str(screenshot_after)
                return candidate

        logger.info(f"브라우저 검증 실패 (실행 안 됨): {url} [{param}]")
        return candidate  # browser_verified=False 그대로

    def _try_payload(
        self,
        browser,
        url: str,
        param: str,
        payload: str,
        cookies: dict,
        xss_type: str
    ) -> tuple:
        """단일 페이로드 브라우저 실행 시도"""
        context = browser.new_context()
        page = context.new_page()

        alert_triggered = False
        screenshot_alert = None
        screenshot_after = None

        def handle_dialog(dialog):
            nonlocal alert_triggered, screenshot_alert
            alert_triggered = True

            # alert 뜬 순간 스크린샷
            screenshot_alert = self._make_screenshot_path(url, param, "alert")
            try:
                page.screenshot(path=str(screenshot_alert))
            except:
                pass

            dialog.accept()

        page.on("dialog", handle_dialog)

        try:
            # 페이로드가 담긴 URL 구성
            test_url = self._build_payload_url(url, param, payload)

            page.goto(test_url, timeout=BROWSER_TIMEOUT, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)  # JS 실행 대기

            if alert_triggered:
                # alert 닫힌 후 페이지 스크린샷
                screenshot_after = self._make_screenshot_path(url, param, "after")
                try:
                    page.screenshot(path=str(screenshot_after))
                except:
                    pass

        except Exception as e:
            logger.debug(f"브라우저 오류: {url} - {e}")
        finally:
            context.close()

        return alert_triggered, screenshot_alert, screenshot_after

    def _build_payload_url(self, url: str, param: str, payload: str) -> str:
        """페이로드가 삽입된 URL 생성"""
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        params[param] = payload

        new_query = urlencode(params)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)

    def _make_screenshot_path(
        self, url: str, param: str, suffix: str
    ) -> Path:
        """스크린샷 저장 경로 생성"""
        domain = urlparse(url).netloc.replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{domain}_{param}_{suffix}.png"
        return self.evidence_dir / filename
