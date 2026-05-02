"""
실제 테스트 스크립트
대상: testphp.vulnweb.com (Acunetix 공식 제공 취약한 테스트 사이트)
      DVWA (로컬 설치 시)

실행 방법:
    python XSS/test_real.py

입력: XSS/input.json  ← 반드시 존재해야 함
"""

import sys
import json
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from xss_scanner import run_xss_scan


def run_test(input_data: dict):
    base_url = input_data.get("base_url", "")
    print(f"\n{'='*60}")
    print(f"테스트 대상: {base_url}")
    print(f"{'='*60}")

    result = run_xss_scan(input_data)

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

    output_dir = Path(__file__).parent / "results"
    output_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"xss_result_{timestamp}.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n[JSON 저장] {output_path}")

    return result


def main():
    input_path = Path(__file__).parent / "input.json"

    if not input_path.exists():
        print(f"[오류] input.json이 없습니다: {input_path}")
        print("       input.json을 생성한 후 다시 실행하세요.")
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        try:
            input_data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[오류] input.json 파싱 실패: {e}")
            print("       JSON 형식이 올바른지 확인하세요. (주석, 변수 할당, trailing comma 불가)")
            sys.exit(1)

    run_test(input_data)


if __name__ == "__main__":
    main()
