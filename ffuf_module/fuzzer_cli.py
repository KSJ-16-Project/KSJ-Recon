"""
K-Shield Jr. Recon 모듈 - Fuzzer CLI (단독 실행용)

fuzzer_module.py의 AggressiveFuzzer 클래스를 인터랙티브하게 실행한다.
Core 시스템이 모듈을 import할 때는 이 파일이 실행되지 않는다.

사용법:
    python fuzzer_cli.py
"""

import json
from fuzzer_module import AggressiveFuzzer


# ====================================================================
# 사용자 입력
# ====================================================================
def get_user_input() -> dict:
    """
    사용자로부터 퍼징 옵션을 입력받는다.
    엔터만 치면 기본값 사용.
    """
    print("=" * 60)
    print("  K-Shield Jr. Portable Fuzzer - CLI")
    print("=" * 60)

    # 1. 타겟 URL
    default_target = "http://testphp.vulnweb.com"
    target = input(f"타겟 URL (엔터 시 기본: {default_target}): ").strip()
    if not target:
        target = default_target

    # 2. 모드 선택
    print("\n모드 선택:")
    print("  1) directory  (디렉토리/파일 퍼징)")
    print("  2) subdomain  (서브도메인 퍼징 - 합법 도메인만!)")
    mode_input = input("선택 (1/2, 기본: 1): ").strip()
    mode = "subdomain" if mode_input == "2" else "directory"

    # 3. depth 설정 (디렉토리 모드만)
    depth = 0
    if mode == "directory":
        print("\nDepth 설정:")
        print("  0 = 재귀 없음 (가장 빠름)")
        print("  1 = 발견된 디렉토리 한 단계 더")
        print("  2 = 두 단계 깊이 (권장 최대)")
        print("  3+ = 깊은 탐색 (시간 매우 오래 걸림)")
        depth_input = input("Depth (기본: 0): ").strip()
        try:
            depth = int(depth_input) if depth_input else 0
            if depth < 0:
                depth = 0
        except ValueError:
            depth = 0

    # 4. 워드리스트
    default_wl = "common.txt" if mode == "directory" else "shubs-subdomains.txt"
    wordlist = input(f"\n워드리스트 (엔터 시 기본: {default_wl}): ").strip()
    if not wordlist:
        wordlist = default_wl

    # 5. 결과 저장 여부
    save_input = input("\n결과를 파일로 저장할까요? (y/n, 기본: y): ").strip().lower()
    save_to = "auto" if save_input != "n" else None

    return {
        "target": target,
        "mode": mode,
        "depth": depth,
        "wordlist": wordlist,
        "save_to": save_to,
    }


# ====================================================================
# 옵션 자동 계산
# ====================================================================
def calculate_options(depth: int, mode: str) -> dict:
    """
    depth/mode에 따라 threads/timeout을 자동 조정.
    - depth가 깊을수록 요청 폭증 → threads 낮춤, timeout 늘림
    - 서브도메인 모드는 비교적 가벼우므로 별도 정책
    """
    if mode == "subdomain":
        return {"threads": 80, "timeout_sec": 600}

    # directory 모드
    if depth == 0:
        return {"threads": 50, "timeout_sec": 300}

    threads = max(10, 50 - (depth * 15))         # depth 1=35, 2=20, 3=10
    timeout_sec = 300 * (depth + 1)              # depth 1=600, 2=900, 3=1200
    return {"threads": threads, "timeout_sec": timeout_sec}


# ====================================================================
# 결과 출력
# ====================================================================
def print_summary(config: dict, runtime_opts: dict):
    """실행 전 설정 요약 출력"""
    print(f"\n[설정 요약]")
    print(f"  타겟       : {config['target']}")
    print(f"  모드       : {config['mode']}")
    if config["mode"] == "directory":
        print(f"  Depth      : {config['depth']} (0=재귀없음)")
    print(f"  워드리스트 : {config['wordlist']}")
    print(f"  Threads    : {runtime_opts['threads']}")
    print(f"  Timeout    : {runtime_opts['timeout_sec']}초")
    print(f"  저장       : {'예 (results/ 폴더)' if config['save_to'] else '아니오'}")
    print()


def print_results(result: dict):
    """결과를 보기 좋게 출력. 재귀 결과는 트리 형태로."""
    if result.get("status") != "ok":
        print(f"\n[!] 실행 실패: {result.get('error', '알 수 없는 오류')}")
        return

    results = result.get("results", [])
    mode = result.get("mode")

    print(f"\n[+] 발견: {len(results)}개")

    if result.get("warnings"):
        for w in result["warnings"]:
            print(f"[!] 경고: {w}")

    if result.get("saved_path"):
        print(f"[+] 결과 저장: {result['saved_path']}")

    print()

    if not results:
        print("  (발견된 항목 없음)")
        return

    if mode == "subdomain":
        for item in results:
            schemes = ",".join(item.get("schemes", ["http"]))
            host = item.get("host", "")
            print(f"  [{item['status']}] {host}  ({schemes})")

    elif mode == "directory":
        for item in results:
            depth = item.get("depth", 1)
            indent = "  " * (depth - 1)
            depth_tag = f"[d{depth}]" if "depth" in item else ""
            print(f"{indent}  {depth_tag}[{item['status']}] {item['url']}  (length: {item['length']})")


def print_status_breakdown(result: dict):
    """status code별 요약 통계 (AI 파이프라인 디버깅용)"""
    results = result.get("results", [])
    if not results:
        return

    breakdown = {}
    for item in results:
        status = item["status"]
        breakdown[status] = breakdown.get(status, 0) + 1

    print("\n[Status 분포]")
    for status in sorted(breakdown.keys()):
        # 우선순위 마커: 401/403은 흥미로운 타겟
        marker = ""
        if status in (401, 403):
            marker = "  ← 인증/권한 필요 (공격 가치 ↑)"
        elif status == 200:
            marker = "  ← 정상 응답"
        elif status in (301, 302):
            marker = "  ← 리다이렉트"
        elif status >= 500:
            marker = "  ← 서버 에러 (이상 동작 가능성)"

        print(f"  {status}: {breakdown[status]}개{marker}")


# ====================================================================
# 메인 진입점
# ====================================================================
def main():
    # 1. 사용자 입력
    config = get_user_input()

    # 2. depth/mode에 따라 threads/timeout 자동 계산
    runtime_opts = calculate_options(config["depth"], config["mode"])

    # 3. 설정 요약 출력
    print_summary(config, runtime_opts)

    # 4. 서브도메인 모드 안전장치 (한 번 더 확인)
    if config["mode"] == "subdomain":
        print("[!] 주의: 서브도메인 퍼징은 명시적 허가받은 도메인에서만 사용하세요.")
        print("    - 본인 소유 도메인")
        print("    - HackerOne/Bugcrowd 등록된 스코프")
        print("    - 격리된 학습 환경 (HackTheBox 등)")
        confirm = input("진행하시겠습니까? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("취소되었습니다.")
            return

    # 5. Fuzzer 인스턴스 생성 및 실행
    fuzzer = AggressiveFuzzer(config["target"])

    # depth가 0보다 크면 recursion 옵션 추가
    recursion_kwargs = {}
    if config["mode"] == "directory" and config["depth"] > 0:
        recursion_kwargs = {
            "recursion": True,
            "recursion_depth": config["depth"],
        }

    result = fuzzer.run_fuzz(
        mode=config["mode"],
        wordlist=config["wordlist"],
        threads=runtime_opts["threads"],
        timeout_sec=runtime_opts["timeout_sec"],
        save_to=config["save_to"],
        verbose=True,            # CLI에서는 진행 로그 켜기
        **recursion_kwargs,
    )

    # 6. 결과 출력
    print_results(result)
    print_status_breakdown(result)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] 사용자가 중단했습니다.")
    except Exception as e:
        print(f"\n[!] 예상치 못한 오류: {e}")