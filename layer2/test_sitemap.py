"""
test_sitemap.py — sitemap.py 디버그 테스트

각 단계에서 타임스탬프와 소요 시간을 출력해
어느 지점에서 멈추는지 확인한다.

Playwright 불필요 — urllib 기반이므로 단독 실행 가능.

실행 (layer2/ 디렉토리에서):
    python test_sitemap.py
"""

import asyncio
import sys
import time

# ── 경로 설정 ─────────────────────────────────────────────────
sys.path.insert(0, r"C:\Projects\ksj\KSJ-Recon")   # layer2 패키지


# ── 테스트 대상 URL ───────────────────────────────────────────
TARGET_URL = "https://www.apple.com/"


# ── 로그 헬퍼 ─────────────────────────────────────────────────
def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def elapsed(t0: float) -> str:
    return f"{time.time() - t0:.1f}s"

def _preview(text: str, n: int = 200) -> str:
    """긴 본문을 n자로 잘라 보여준다."""
    text = text.strip()
    return text[:n] + ("..." if len(text) > n else "")


# ── STEP 0: 임포트 확인 ───────────────────────────────────────
log("STEP 0 | 임포트 확인")

try:
    from layer2.sitemap import (
        fetch_url,
        fetch_robots,
        fetch_sitemap,
        check_security_files,
    )
    log(f"        layer2.sitemap OK  (TARGET_URL={TARGET_URL})")
except ImportError as e:
    log(f"        [실패] layer2.sitemap 임포트 오류: {e}")
    log("        → C:\\Projects\\ksj\\KSJ-Recon\\layer2\\__init__.py 가 있는지 확인")
    sys.exit(1)


async def main() -> None:

    # ── STEP 1: fetch_url — 기본 GET 동작 확인 ───────────────
    # [학습 포인트] asyncio.to_thread 로 urllib(블로킹) 을 비동기 실행하는지 검증
    log("STEP 1 | fetch_url 기본 동작 확인 → http://example.com")
    t0 = time.time()
    try:
        status, body = await asyncio.wait_for(
            fetch_url("http://example.com", timeout=10),
            timeout=15,
        )
        if status == 200 and body:
            log(f"        [성공] status={status}  body={len(body)}B ({elapsed(t0)})")
            log(f"        본문 미리보기: {_preview(body, 120)}")
        else:
            log(f"        [경고] status={status}  body={len(body)}B ({elapsed(t0)})")
    except asyncio.TimeoutError:
        log(f"        [타임아웃] 15초 초과 ({elapsed(t0)})")
        log("        → 네트워크 연결 상태 확인")
        return
    except Exception as e:
        log(f"        [오류] {type(e).__name__}: {e} ({elapsed(t0)})")
        return

    # ── STEP 2: fetch_robots — robots.txt 파싱 ───────────────
    log(f"STEP 2 | fetch_robots → {TARGET_URL}")
    t0 = time.time()
    disallowed: list[str] = []
    sitemap_urls: list[str] = []
    try:
        disallowed, sitemap_urls = await asyncio.wait_for(
            fetch_robots(TARGET_URL),
            timeout=15,
        )
        log(f"        [성공] ({elapsed(t0)})")
        log(f"        Disallow  : {len(disallowed)}개  예시={disallowed[:5]}")
        log(f"        Sitemap   : {len(sitemap_urls)}개  목록={sitemap_urls}")
    except asyncio.TimeoutError:
        log(f"        [타임아웃] 15초 초과 ({elapsed(t0)})")
        log("        → robots.txt 응답 없음 (이후 단계는 /sitemap.xml 직접 시도)")
    except Exception as e:
        log(f"        [오류] {type(e).__name__}: {e} ({elapsed(t0)})")

    # ── STEP 3: fetch_sitemap — sitemap.xml 파싱 ─────────────
    # robots.txt 에서 sitemap URL 을 얻었으면 첫 번째를 사용,
    # 없으면 /sitemap.xml 을 직접 시도한다.
    from urllib.parse import urljoin, urlparse
    base = f"{urlparse(TARGET_URL).scheme}://{urlparse(TARGET_URL).netloc}"

    if sitemap_urls:
        seed_sitemap = sitemap_urls[0]
        log(f"STEP 3 | fetch_sitemap (robots.txt 에서 발견) → {seed_sitemap}")
    else:
        seed_sitemap = urljoin(base, "/sitemap.xml")
        log(f"STEP 3 | fetch_sitemap (기본 경로 시도) → {seed_sitemap}")

    t0 = time.time()
    try:
        urls = await asyncio.wait_for(
            fetch_sitemap(seed_sitemap, limit=5),
            timeout=30,
        )
        if urls:
            log(f"        [성공] URL {len(urls)}개 수집 ({elapsed(t0)})")
            log(f"        예시 (상위 5개):")
            for u in urls[:5]:
                log(f"          {u}")
        else:
            log(f"        [결과 없음] sitemap 파싱 실패 또는 URL 없음 ({elapsed(t0)})")
            log("        → 사이트가 sitemap.xml 을 제공하지 않는 경우일 수 있음")
    except asyncio.TimeoutError:
        log(f"        [타임아웃] 30초 초과 ({elapsed(t0)})")
    except Exception as e:
        log(f"        [오류] {type(e).__name__}: {e} ({elapsed(t0)})")

    # ── STEP 4: check_security_files — 보안 파일 탐지 ────────
    # [core 옵션에 따라 실행 여부 결정] 결과는 LLM 에 전달하여 보안 가치 판단
    log(f"STEP 4 | check_security_files → {TARGET_URL}")
    t0 = time.time()
    try:
        found = await asyncio.wait_for(
            check_security_files(TARGET_URL),
            timeout=20,
        )
        if found:
            log(f"        [성공] {len(found)}개 파일 발견 ({elapsed(t0)})")
            for path, body in found.items():
                log(f"          {path}  ({len(body)}B)")
                log(f"            내용 미리보기: {_preview(body, 150)}")
        else:
            log(f"        [결과 없음] 보안 파일 없음 ({elapsed(t0)})")
            log("        → 탐지 대상: /.well-known/security.txt, /security.txt,")
            log("                     /crossdomain.xml, /clientaccesspolicy.xml")
    except asyncio.TimeoutError:
        log(f"        [타임아웃] 20초 초과 ({elapsed(t0)})")
    except Exception as e:
        log(f"        [오류] {type(e).__name__}: {e} ({elapsed(t0)})")

    log("완료 — 모든 sitemap 함수 실행")


if __name__ == "__main__":
    asyncio.run(main())
