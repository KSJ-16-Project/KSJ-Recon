"""
XSS Scanner Module
------------------
입력: Middle Core JSON
출력: XSS 탐지 결과 JSON (보고서 LLM용)

탐지 범위:
- Reflected XSS (GET/POST)
- Stored XSS (POST 저장 → Crawler/Fuzzer URL 순회)

스코프 외:
- DOM XSS (보고서에 명시)
- WAF 우회 (감지만 하고 보고서에 명시)
"""

import subprocess
import sys
import json
import logging
from pathlib import Path
from datetime import datetime


def ensure_dependencies():
    """필요한 패키지 자동 설치"""
    packages = ["requests", "playwright"]
    for package in packages:
        try:
            __import__(package)
        except ImportError:
            print(f"[설치 중] {package}...")
            subprocess.run([
                sys.executable, "-m", "pip", "install", package,
                "--break-system-packages", "-q"
            ])

    # Chromium 설치 확인
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch()
            browser.close()
    except Exception:
        print("[설치 중] Chromium (1~2분 소요)...")
        subprocess.run([
            sys.executable, "-m", "playwright", "install", "chromium"
        ])


ensure_dependencies()

# 스크립트 위치 기준으로 경로를 잡아 어디서 실행해도 import 가능
sys.path.insert(0, str(Path(__file__).parent))

from reflected_xss import ReflectedXSSScanner
from stored_xss import StoredXSSScanner
from browser_verifier import BrowserVerifier
from result_builder import ResultBuilder

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)


class XSSScanner:
    def __init__(self, input_data: dict):
        self.input_data = input_data
        self.base_url = input_data.get("base_url", "")
        self.urls = input_data.get("urls", [])
        self.evidence_dir = Path(__file__).parent / "evidence"
        self.evidence_dir.mkdir(exist_ok=True)
        self.result_builder = ResultBuilder()

    def run(self) -> dict:
        logger.info(f"XSS 스캔 시작: {self.base_url}")
        logger.info(f"총 대상 URL: {len(self.urls)}개")

        all_results = []

        # 1단계: Reflected XSS (requests 기반)
        logger.info("=== Reflected XSS 스캔 시작 ===")
        reflected_scanner = ReflectedXSSScanner(self.urls)
        reflected_candidates = reflected_scanner.scan()
        logger.info(f"Reflected XSS 후보: {len(reflected_candidates)}개")

        # 2단계: Stored XSS (POST URL 대상)
        logger.info("=== Stored XSS 스캔 시작 ===")
        stored_scanner = StoredXSSScanner(self.urls)
        stored_candidates = stored_scanner.scan()
        logger.info(f"Stored XSS 후보: {len(stored_candidates)}개")

        # 3단계: Playwright 브라우저 검증 (의심 URL 전체)
        all_candidates = reflected_candidates + stored_candidates

        if all_candidates:
            logger.info("=== 브라우저 검증 시작 ===")
            verifier = BrowserVerifier(self.evidence_dir)
            verified_results = verifier.verify(all_candidates)
            all_results.extend(verified_results)
        
        # 결과 빌드
        final_output = self.result_builder.build(
            results=all_results,
            total_tested=len(self.urls),
            base_url=self.base_url
        )

        logger.info(f"스캔 완료 - HIGH: {final_output['summary']['high']}, "
                   f"MEDIUM: {final_output['summary']['medium']}, "
                   f"LOW: {final_output['summary']['low']}")

        return final_output


def run_xss_scan(input_json: dict) -> dict:
    """Middle Core에서 호출하는 메인 함수"""
    scanner = XSSScanner(input_json)
    return scanner.run()


if __name__ == "__main__":
    BASE_DIR = Path(__file__).parent

    # 1순위: CLI 인자, 2순위: input.json, 3순위: 기본 테스트 데이터
    if len(sys.argv) > 1:
        input_path = Path(sys.argv[1])
    else:
        input_path = BASE_DIR / "input.json"

    if input_path.exists():
        logger.info(f"입력 파일 로드: {input_path}")
        with open(input_path, "r", encoding="utf-8") as f:
            input_data = json.load(f)
    else:
        logger.warning("input.json 없음 — 기본 테스트 데이터 사용")
        input_data = {
            "base_url": "http://testphp.vulnweb.com",
            "urls": [
                {
                    "url": "http://testphp.vulnweb.com/search.php?test=query",
                    "type": "spider",
                    "method": "GET",
                    "params": {"test": "query"},
                    "cookies": {},
                    "headers": {}
                }
            ]
        }

    result = run_xss_scan(input_data)

    output_dir = Path(__file__).parent / "results"
    output_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"xss_result_{timestamp}.json"

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    logger.info(f"결과 저장: {output_path}")
