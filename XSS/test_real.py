"""
실제 테스트 스크립트
대상: testphp.vulnweb.com (Acunetix 공식 제공 취약한 테스트 사이트)
      DVWA (로컬 설치 시)

실행 방법:
    python tests/test_real.py                    # 기본 테스트
    python tests/test_real.py --target dvwa      # DVWA 테스트
    python tests/test_real.py --no-browser       # 브라우저 검증 없이
"""

import sys
import json
import argparse
import logging
from pathlib import Path

# 상위 디렉터리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from xss_scanner import run_xss_scan

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s"
)


# ============================================================
# 테스트 데이터 정의
# ============================================================

# 1. testphp.vulnweb.com (인터넷 연결 필요, 실제 취약한 사이트)
VULNWEB_INPUT = {
    "base_url": "http://testphp.vulnweb.com",
    "urls": [
        {
            "url": "http://testphp.vulnweb.com/search.php",
            "type": "spider",
            "method": "GET",
            "params": {"test": "query"},
            "cookies": {},
            "headers": {}
        },
        {
            "url": "http://testphp.vulnweb.com/listproducts.php",
            "type": "spider",
            "method": "GET",
            "params": {"cat": "1"},
            "cookies": {},
            "headers": {}
        },
        {
            "url": "http://testphp.vulnweb.com/hpp/",
            "type": "spider",
            "method": "GET",
            "params": {"pp": "12"},
            "cookies": {},
            "headers": {}
        },
    ]
}

# 2. DVWA (로컬 설치 필요, http://localhost/dvwa)
# Low 시큐리티 레벨에서 테스트
DVWA_INPUT = {
    "base_url": "http://localhost/dvwa",
    "urls": [
        {
            "url": "http://localhost/dvwa/vulnerabilities/xss_r/",
            "type": "spider",
            "method": "GET",
            "params": {"name": "test"},
            "cookies": {
                "PHPSESSID": "your_session_id_here",  # DVWA 로그인 후 세션 ID
                "security": "low"
            },
            "headers": {}
        },
        {
            "url": "http://localhost/dvwa/vulnerabilities/xss_s/",
            "type": "spider",
            "method": "POST",
            "params": {
                "txtName": "test",
                "mtxMessage": "hello",
                "btnSign": "Sign Guestbook"
            },
            "cookies": {
                "PHPSESSID": "your_session_id_here",
                "security": "low"
            },
            "headers": {}
        },
    ]
}

# 3. 필드 누락 테스트 (optional 필드 처리 확인)
MISSING_FIELDS_INPUT = {
    "base_url": "http://testphp.vulnweb.com",
    "urls": [
        {
            # cookies, headers 없음 → 기본값으로 처리되어야 함
            "url": "http://testphp.vulnweb.com/search.php",
            "type": "spider",
            "method": "GET",
            "params": {"test": "query"}
        },
        {
            # params도 없음 → URL에서 파싱
            "url": "http://testphp.vulnweb.com/search.php?test=query",
            "type": "spider",
            "method": "GET"
        },
    ]
}


# ============================================================
# 테스트 실행
# ============================================================

def run_test(input_data: dict, test_name: str):
    print(f"\n{'='*60}")
    print(f"테스트: {test_name}")
    print(f"{'='*60}")

    result = run_xss_scan(input_data)

    # 결과 출력
    summary = result.get("summary", {})
    print(f"\n[결과 요약]")
    print(f"  총 테스트 URL: {summary.get('total_tested')}개")
    print(f"  발견된 취약점: {summary.get('total_found')}개")
    print(f"  HIGH: {summary.get('high')}")
    print(f"  MEDIUM: {summary.get('medium')}")
    print(f"  LOW: {summary.get('low')}")
    print(f"  WAF 감지: {summary.get('waf_detected')}")

    if result.get("xss_results"):
        print(f"\n[발견된 취약점]")
        for finding in result["xss_results"]:
            print(f"\n  URL: {finding['url']}")
            print(f"  파라미터: {finding['param']}")
            print(f"  타입: {finding['xss_type']}")
            print(f"  위험도: {finding['risk_level']}")
            print(f"  컨텍스트: {finding['context']}")
            print(f"  브라우저 확인: {finding['browser_verified']}")
            if finding.get("screenshot_alert"):
                print(f"  스크린샷(alert): {finding['screenshot_alert']}")
            if finding.get("screenshot_after"):
                print(f"  스크린샷(after): {finding['screenshot_after']}")

    # JSON 파일로 저장
    output_path = Path(f"tests/output_{test_name.replace(' ', '_')}.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n[JSON 저장] {output_path}")

    return result


def main():
    parser = argparse.ArgumentParser(description="XSS 모듈 실제 테스트")
    parser.add_argument(
        "--target",
        choices=["vulnweb", "dvwa", "missing_fields", "all"],
        default="vulnweb",
        help="테스트 대상 선택"
    )
    args = parser.parse_args()

    Path("tests").mkdir(exist_ok=True)

    if args.target == "vulnweb" or args.target == "all":
        run_test(VULNWEB_INPUT, "vulnweb")

    if args.target == "dvwa" or args.target == "all":
        print("\n[주의] DVWA 테스트는 로컬에 DVWA가 설치되어 있어야 합니다.")
        print("       DVWA_INPUT의 PHPSESSID를 실제 값으로 변경 후 실행하세요.")
        run_test(DVWA_INPUT, "dvwa")

    if args.target == "missing_fields" or args.target == "all":
        run_test(MISSING_FIELDS_INPUT, "missing_fields")


if __name__ == "__main__":
    main()
