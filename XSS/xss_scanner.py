"""
XSS Scanner Module
------------------
입력: Middle Core JSON
출력: XSS 탐지 결과 JSON (보고서 LLM용)

탐지 범위:
- Reflected XSS (GET/POST)
- Stored XSS (POST 저장 → Crawler/Fuzzer URL 순회)
- DOM Stored XSS (Playwright 폼 조작)

스코프 외:
- DOM XSS (보고서에 명시)
- WAF 우회 (감지만 하고 보고서에 명시)
"""

import signal
import subprocess
import sys
import json
import logging
from pathlib import Path
from datetime import datetime


# ------------------------------------------------------------------ #
#  의존성 자동 설치                                                    #
# ------------------------------------------------------------------ #

def ensure_dependencies():
    """Python 패키지 및 Chromium 자동 설치"""
    for package in ["requests", "playwright"]:
        try:
            __import__(package)
        except ImportError:
            print(f"[설치] {package}...")
            subprocess.run([
                sys.executable, "-m", "pip", "install", package,
                "--break-system-packages", "-q"
            ], check=False)

    _ensure_chromium()


def _ensure_chromium():
    """Chromium 바이너리 및 시스템 라이브러리 설치"""
    cache_dir = Path.home() / ".cache/ms-playwright"
    chromium_installed = (
        cache_dir.exists()
        and any(d.name.startswith("chromium") for d in cache_dir.iterdir() if d.is_dir())
    )

    if not chromium_installed:
        print("[설치] Chromium 다운로드 중 (1~2분)...")
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            check=False
        )

    if _can_launch_chromium():
        return

    print("[설치] Chromium 시스템 라이브러리 설치 중...")
    r = subprocess.run(
        [sys.executable, "-m", "playwright", "install-deps", "chromium"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        print("[설치] 관리자 권한으로 재시도...")
        subprocess.run(
            ["sudo", sys.executable, "-m", "playwright", "install-deps", "chromium"],
            check=False
        )

    if not _can_launch_chromium():
        print("[경고] Chromium 실행 불가 — 브라우저 검증 없이 진행됩니다.")


def _can_launch_chromium() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch()
            b.close()
        return True
    except Exception:
        return False


ensure_dependencies()

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


# ------------------------------------------------------------------ #
#  Ctrl+C 핸들러                                                      #
# ------------------------------------------------------------------ #

_running_scanner = None


def _handle_sigint(_sig, _frame):
    print("\n[중단] 스캔이 중단되었습니다. 현재까지의 결과를 저장합니다.")
    if _running_scanner is not None:
        _running_scanner.save_partial()
    sys.exit(0)


signal.signal(signal.SIGINT, _handle_sigint)


# ------------------------------------------------------------------ #
#  입력 JSON 검증                                                      #
# ------------------------------------------------------------------ #

def validate_input(input_json: dict) -> dict:
    """입력 JSON 스펙 검증. 문제 있으면 즉시 종료."""
    if not input_json.get("base_url"):
        sys.exit("[오류] input.json에 'base_url'이 없습니다.")

    urls = input_json.get("urls", [])
    if not urls:
        sys.exit("[오류] input.json의 'urls'가 비어 있습니다.")

    valid = [item for item in urls if item.get("url")]
    skipped = len(urls) - len(valid)
    if skipped:
        logger.warning(f"'url' 필드 없는 항목 {skipped}개 스킵")
    if not valid:
        sys.exit("[오류] 유효한 url_item이 없습니다.")

    return {**input_json, "urls": valid}


# ------------------------------------------------------------------ #
#  XSS 스캐너                                                         #
# ------------------------------------------------------------------ #

class XSSScanner:
    def __init__(self, input_data: dict):
        global _running_scanner
        _running_scanner = self

        self.input_data = input_data
        self.base_url = input_data.get("base_url", "")
        self.urls = input_data.get("urls", [])
        self.evidence_dir = Path(__file__).parent / "evidence"
        self.evidence_dir.mkdir(exist_ok=True)
        self.result_builder = ResultBuilder()
        self.auth = self._resolve_auth(input_data)

        self._partial_results = []
        self._scan_errors = []

    def _resolve_auth(self, input_data: dict) -> dict:
        """input에서 session_id/token 추출. 둘 다 없으면 login.py 호출"""
        session_id = input_data.get("session_id")
        token = input_data.get("token")

        if not session_id and not token:
            logger.info("input에 인증 정보 없음 → login.py 호출")
            try:
                from login import get_auth
                auth = get_auth()
                session_id = auth.get("session_id")
                token = auth.get("token")
                logger.info("login.py에서 인증 정보 획득 완료")
            except Exception as e:
                logger.warning(f"login.py 호출 실패 (인증 없이 진행): {e}")

        return {"session_id": session_id, "token": token}

    def save_partial(self):
        """중단 시 현재까지 결과를 output_partial.json으로 저장"""
        auth_keys = [k for k, v in self.auth.items() if v]
        output = self.result_builder.build(
            results=self._partial_results,
            total_tested=len(self.urls),
            base_url=self.base_url,
            auth_used=auth_keys,
            scan_errors=self._scan_errors
        )
        output_dir = Path(__file__).parent / "results"
        output_dir.mkdir(exist_ok=True)
        path = output_dir / "output_partial.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, indent=2)
        print(f"[저장] {path}")

    def run(self) -> dict:
        logger.info(f"XSS 스캔 시작: {self.base_url}")
        logger.info(f"총 대상 URL: {len(self.urls)}개")

        auth_keys = [k for k, v in self.auth.items() if v]
        if auth_keys:
            logger.info(f"인증 정보 적용: {', '.join(auth_keys)}")
        else:
            logger.info("인증 정보 없음 (비인증 스캔)")

        all_results = []

        # 1단계: Reflected XSS
        logger.info("=== Reflected XSS 스캔 시작 ===")
        reflected_scanner = ReflectedXSSScanner(self.urls, auth=self.auth)
        reflected_candidates = reflected_scanner.scan()
        self._scan_errors.extend(reflected_scanner.errors)
        logger.info(f"Reflected XSS 후보: {len(reflected_candidates)}개")

        # 2단계: Stored XSS - POST 방식
        logger.info("=== Stored XSS 스캔 시작 (POST) ===")
        stored_scanner = StoredXSSScanner(self.urls, auth=self.auth)
        stored_candidates = stored_scanner.scan()
        self._scan_errors.extend(stored_scanner.errors)
        logger.info(f"Stored XSS (POST) 후보: {len(stored_candidates)}개")

        # 3단계: Stored XSS - DOM 방식
        logger.info("=== Stored XSS 스캔 시작 (DOM) ===")
        dom_stored_results = stored_scanner.scan_dom()
        all_results.extend(dom_stored_results)
        self._partial_results = list(all_results)  # 부분 저장 갱신

        # 4단계: 브라우저 검증 (Reflected + POST Stored)
        needs_verify = reflected_candidates + stored_candidates
        if needs_verify:
            logger.info("=== 브라우저 검증 시작 ===")
            verifier = BrowserVerifier(self.evidence_dir)

            def on_verified(result):
                self._partial_results.append(result)

            verified_results = verifier.verify(needs_verify, on_result=on_verified)
            all_results.extend(verified_results)

        final_output = self.result_builder.build(
            results=all_results,
            total_tested=len(self.urls),
            base_url=self.base_url,
            auth_used=auth_keys,
            scan_errors=self._scan_errors
        )

        logger.info(
            f"스캔 완료 - HIGH: {final_output['summary']['high']}, "
            f"MEDIUM: {final_output['summary']['medium']}, "
            f"LOW: {final_output['summary']['low']}, "
            f"오류: {len(self._scan_errors)}건"
        )

        return final_output


def run_xss_scan(input_json: dict) -> dict:
    """Middle Core에서 호출하는 메인 함수"""
    input_json = validate_input(input_json)
    scanner = XSSScanner(input_json)
    return scanner.run()


if __name__ == "__main__":
    BASE_DIR = Path(__file__).parent

    if len(sys.argv) > 1:
        input_path = Path(sys.argv[1])
    else:
        input_path = BASE_DIR / "input.json"

    if not input_path.exists():
        sys.exit(f"[오류] input.json이 없습니다: {input_path}")

    with open(input_path, "r", encoding="utf-8") as f:
        try:
            input_data = json.load(f)
        except json.JSONDecodeError as e:
            sys.exit(f"[오류] input.json 파싱 실패: {e}")

    result = run_xss_scan(input_data)

    output_dir = BASE_DIR / "results"
    output_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"xss_result_{timestamp}.json"

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    logger.info(f"결과 저장: {output_path}")
