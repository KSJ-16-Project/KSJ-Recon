"""
K-Shield Jr. Recon 모듈 - Fuzzer CLI (단독 실행용)

inputs/ 폴더의 JSON 파일을 읽어 자동으로 퍼징을 수행한다.
사용자 입력 없이 JSON → 퍼징 → 결과 저장까지 자동 실행.

Spider 연동 JSON 형식:
    {
        "base_url": "https://target.com",
        "tld1": "target.com",
        "difficulty": 1,
        "spider_urls": [
            "https://target.com/api/users",
            "https://target.com/shop/products"
        ]
    }

사용법:
    # inputs/ 폴더에 JSON 파일이 하나면 자동 선택
    python fuzzer_cli.py

    # 직접 파일 지정
    python fuzzer_cli.py --input inputs/domains.json
"""

import json
import sys
import argparse
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from fuzzer_module import AggressiveFuzzer


# ====================================================================
# 설정 상수
# ====================================================================
BASE_DIR    = Path(__file__).resolve().parent
INPUTS_DIR  = BASE_DIR / "inputs"
RESULTS_DIR = BASE_DIR / "results"


# ====================================================================
# JSON 로드
# ====================================================================
def load_input(input_path: str = None) -> dict:
    """
    input_path 지정 시 해당 파일,
    아니면 inputs/ 폴더에서 자동 탐색.
    파일이 하나면 자동 선택, 여러 개면 가장 최신 파일 선택.
    """
    if input_path:
        path = Path(input_path)
        if not path.exists():
            print(f"[-] 파일 없음: {path}")
            sys.exit(1)
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    if not INPUTS_DIR.exists():
        print(f"[-] inputs/ 폴더 없음: {INPUTS_DIR}")
        sys.exit(1)

    jsons = sorted(INPUTS_DIR.glob("*.json"))
    if not jsons:
        print(f"[-] inputs/ 폴더에 JSON 파일 없음")
        sys.exit(1)

    if len(jsons) == 1:
        path = jsons[0]
        print(f"[*] 자동 선택: {path.name}")
    else:
        path = max(jsons, key=lambda p: p.stat().st_mtime)
        print(f"[*] 최신 파일 선택: {path.name}")

    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validate_input(data: dict) -> dict:
    """
    입력 JSON 유효성 검사 및 기본값 보완.
    """
    if "base_url" not in data:
        print("[-] JSON에 base_url 필드가 없습니다.")
        sys.exit(1)

    base_url = data["base_url"].rstrip("/")
    if not base_url.startswith("http"):
        base_url = "https://" + base_url

    # tld1 없으면 base_url에서 자동 추출
    if "tld1" not in data:
        host = urlparse(base_url).netloc or base_url
        host = host.split(":")[0]
        tld1 = ".".join(host.split(".")[-2:]) if "." in host else host
        data["tld1"] = tld1
        print(f"[*] tld1 자동 추출: {tld1}")

    # difficulty 없으면 기본 1
    if "difficulty" not in data:
        data["difficulty"] = 1
        print(f"[*] difficulty 기본값: 1 (이지)")

    if data["difficulty"] not in [1, 2]:
        print(f"[-] difficulty는 1 또는 2여야 합니다.")
        sys.exit(1)

    data["base_url"]    = base_url
    data["spider_urls"] = data.get("spider_urls", [])

    return data


# ====================================================================
# 실행 전 요약 출력
# ====================================================================
def print_config(config: dict):
    diff_label = {
        1: "이지 (raft-small, ~17,000개, depth 0)",
        2: "하드 (raft-large, ~62,000개, depth 자동)",
    }.get(config["difficulty"], "알 수 없음")

    print(f"\n{'=' * 60}")
    print(f"  [실행 설정]")
    print(f"{'=' * 60}")
    print(f"  base_url   : {config['base_url']}")
    print(f"  tld1       : {config['tld1']}")
    print(f"  난이도     : {config['difficulty']} - {diff_label}")
    print(f"  spider_urls: {len(config['spider_urls'])}개")
    for url in config["spider_urls"]:
        print(f"    → {url}")
    print(f"{'=' * 60}\n")


# ====================================================================
# 결과 출력
# ====================================================================
def print_result(result: dict):
    if result.get("status") != "ok":
        print(f"  [-] 실패: {result.get('error', '알 수 없는 오류')}")
        return

    results = result.get("results", [])
    mode    = result.get("mode")

    print(f"  [+] 발견: {len(results)}개")

    if result.get("warnings"):
        for w in result["warnings"]:
            print(f"  [!] 경고: {w}")

    if result.get("saved_path"):
        print(f"  [+] 저장: {result['saved_path']}")

    if not results:
        return

    # 상태코드 분포
    breakdown = {}
    for r in results:
        code = r.get("status", 0)
        breakdown[code] = breakdown.get(code, 0) + 1
    print(f"  상태코드: {' / '.join(f'{k}:{v}' for k, v in sorted(breakdown.items()))}")

    # HIGH risk 출력
    if mode == "directory":
        high = [r for r in results if r.get("risk") == "HIGH"]
        if high:
            print(f"\n  ⚠️  고위험 경로 ({len(high)}개):")
            for r in high:
                print(f"    [{r['status']}] {r['url']}")


# ====================================================================
# 퍼징 실행
# ====================================================================
def run_all(config: dict):
    base_url    = config["base_url"]
    tld1        = config["tld1"]
    difficulty  = config["difficulty"]
    spider_urls = config["spider_urls"]

    RESULTS_DIR.mkdir(exist_ok=True)

    # ── 공통 저장 폴더 미리 생성 ──
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    host      = urlparse(base_url).netloc or base_url
    safe_host = "".join(c if c.isalnum() or c in "-_" else "_" for c in host)
    run_dir   = RESULTS_DIR / f"{safe_host}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    all_results = []
    step_total  = 2 + len(spider_urls)
    step        = 0

    # ── 1. base URL 디렉터리 퍼징 ──
    step += 1
    print(f"[{step}/{step_total}] 디렉터리 퍼징: {base_url}")
    print("-" * 50)

    fuzzer1 = AggressiveFuzzer(base_url)
    result1 = fuzzer1.run_fuzz(
        mode="directory",
        difficulty=difficulty,
        spider_url_count=len(spider_urls),
        save_to=str(run_dir / "fuzzer_directory.json"),
        verbose=True,
    )
    print_result(result1)
    all_results.append(result1)

    # ── 2. 서브도메인 퍼징 ──
    step += 1
    subdomain_target = f"https://{tld1}"
    print(f"\n[{step}/{step_total}] 서브도메인 퍼징: {subdomain_target}")
    print("-" * 50)

    fuzzer2 = AggressiveFuzzer(subdomain_target)
    result2 = fuzzer2.run_fuzz(
        mode="subdomain",
        difficulty=difficulty,
        save_to=str(run_dir / "fuzzer_subdomain.json"),
        verbose=True,
    )
    print_result(result2)
    all_results.append(result2)

    # ── 3. Spider URL 퍼징 ──
    for i, url in enumerate(spider_urls, 1):
        step += 1
        print(f"\n[{step}/{step_total}] Spider URL 퍼징: {url}")
        print("-" * 50)

        fuzzer3 = AggressiveFuzzer(url)
        result3 = fuzzer3.run_fuzz(
            mode="directory",
            difficulty=difficulty,
            spider_url_count=len(spider_urls),
            save_to=str(run_dir / f"fuzzer_spider_{i}.json"),
            verbose=True,
        )
        print_result(result3)
        all_results.append(result3)

    # ── 전체 결과 통합 저장 ──
    save_path = run_dir / "fuzzer_all.json"

    with open(save_path, "w", encoding="utf-8") as f:
        json.dump({
            "base_url":    base_url,
            "tld1":        tld1,
            "difficulty":  difficulty,
            "spider_urls": spider_urls,
            "timestamp":   datetime.now().isoformat(),
            "results":     all_results,
        }, f, indent=2, ensure_ascii=False)

    # 최종 요약
    total_found = sum(len(r.get("results", [])) for r in all_results)
    total_high  = sum(
        len([x for x in r.get("results", []) if x.get("risk") == "HIGH"])
        for r in all_results
    )

    print(f"\n{'=' * 60}")
    print(f"  전체 퍼징 완료")
    print(f"  총 발견:   {total_found}개")
    print(f"  고위험:    {total_high}개")
    print(f"  저장 폴더: {run_dir}")
    print(f"  통합 저장: {save_path}")
    print(f"{'=' * 60}")


# ====================================================================
# 메인
# ====================================================================
def main():
    parser = argparse.ArgumentParser(description="KSJ Recon - Fuzzer CLI")
    parser.add_argument(
        "--input", "-i",
        type=str,
        default=None,
        help="입력 JSON 파일 경로 (기본: inputs/ 폴더 자동 탐색)"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  K-Shield Jr. Portable Fuzzer")
    print("=" * 60)

    # JSON 로드 및 유효성 검사
    raw    = load_input(args.input)
    config = validate_input(raw)

    # 설정 출력
    print_config(config)

    # 자동 실행
    print("[*] 퍼징 시작...\n")
    run_all(config)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] 사용자가 중단했습니다.")
    except Exception as e:
        print(f"\n[!] 예상치 못한 오류: {e}")
        raise