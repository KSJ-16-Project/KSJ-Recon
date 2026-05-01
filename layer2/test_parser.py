"""
test_parser.py — parser.py 디버그 테스트

각 단계에서 타임스탬프와 소요 시간을 출력해
어느 지점에서 멈추는지 확인한다.

실행 (layer2/ 디렉토리에서):
    python test_parser.py

로그인 테스트 실행:
    TEST_LOGIN = True 로 변경 후 실행
"""

import asyncio
import sys
import time

# ── 경로 설정 ─────────────────────────────────────────────────
sys.path.insert(0, r"C:\Projects\ksj\KSJ-Recon")   # layer1 패키지
sys.path.insert(0, r"C:\Users\yelim\webcrawler")     # crawler 패키지


# ── 익명 크롤링 대상 URL ──────────────────────────────────────
TARGET_URL = "https://www.hotspotfan.online"

# ── 로그인 테스트 설정 ────────────────────────────────────────
# TEST_LOGIN = True 로 바꾸면 STEP 6~8 실행
TEST_LOGIN = True

# LOGIN_URL: 로그인 폼이 있는 페이지.
#   TARGET_URL 에 로그인 폼이 있으면 동일하게 두면 됨 (STEP 4 결과 재사용).
#   별도 로그인 페이지가 있으면 해당 URL 로 변경.
LOGIN_URL       = TARGET_URL
AFTER_LOGIN_URL = TARGET_URL   # 로그인 후 parser 를 실행할 보호 페이지

USERNAME = "s@a.com"
PASSWORD = "qwer1234!"
# 셀렉터는 하드코딩하지 않는다.
# STEP 5 에서 parser 가 폼을 탐지하고, 필드 name 속성으로 셀렉터를 자동 생성한다.


# ── 로그 헬퍼 ─────────────────────────────────────────────────
def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def elapsed(t0: float) -> str:
    return f"{time.time() - t0:.1f}s"


# ── STEP 0: 임포트 확인 ───────────────────────────────────────
log("STEP 0 | 임포트 확인")

try:
    from layer1.browser import BrowserManager
    from layer1.render import render, probe
    log("        layer1 OK")
except ImportError as e:
    log(f"        [실패] layer1 임포트 오류: {e}")
    log("        → C:\\Projects\\ksj\\KSJ-Recon\\layer1\\__init__.py 가 있는지 확인")
    sys.exit(1)

try:
    from crawler.parser import (
        detect_csr_framework,
        detect_render_type,
        detect_technologies,
        extract_comments,
        extract_endpoints,
        extract_forms,
        extract_links,
        extract_routes_from_js,
        extract_scripts,
        extract_url_params,
        parse_cookies,
    )
    log(f"        crawler.parser OK  (TARGET_URL={TARGET_URL})")
except ImportError as e:
    log(f"        [실패] crawler.parser 임포트 오류: {e}")
    sys.exit(1)


def _find_login_form(html: str):
    """
    HTML 에서 로그인 폼을 자동 탐지한다.
    password 필드가 있는 첫 번째 폼을 반환. 없으면 None.
    """
    forms = extract_forms(html)
    return next(
        (f for f in forms if any(field.type == "password" for field in f.fields)),
        None,
    )


async def main() -> None:

    # ── STEP 1: Playwright + Chromium 동작 확인 ───────────────
    log("STEP 1 | Playwright + Chromium probe...")
    t0 = time.time()
    try:
        ok, msg = await asyncio.wait_for(probe(), timeout=20)
        if not ok:
            log(f"        [실패] {msg} ({elapsed(t0)})")
            log("        → 'playwright install chromium' 실행 여부 확인")
            return
        log(f"        [성공] {msg} ({elapsed(t0)})")
    except asyncio.TimeoutError:
        log(f"        [타임아웃] 20초 초과 ({elapsed(t0)})")
        log("        → Chromium 실행 자체가 안 되는 상태")
        return

    # ── STEP 2: BrowserManager 시작 ───────────────────────────
    log("STEP 2 | BrowserManager 시작 (headless=False — 브라우저 창 확인)")
    t0 = time.time()
    bm = BrowserManager(headless=False)
    try:
        await asyncio.wait_for(bm.__aenter__(), timeout=15)
        log(f"        [성공] 브라우저 열림 ({elapsed(t0)})")
    except asyncio.TimeoutError:
        log(f"        [타임아웃] 15초 초과 ({elapsed(t0)})")
        return
    except Exception as e:
        log(f"        [오류] {type(e).__name__}: {e}")
        return

    try:
        # ── STEP 3: about:blank 렌더링 ────────────────────────
        log("STEP 3 | about:blank 렌더링 (render 기본 동작 확인)...")
        t0 = time.time()
        try:
            result = await asyncio.wait_for(
                render(bm.browser, "about:blank", timeout=10),
                timeout=15,
            )
            if result is None:
                log(f"        [실패] render() 가 None 반환 ({elapsed(t0)})")
                return
            log(f"        [성공] status={result.status} ({elapsed(t0)})")
        except asyncio.TimeoutError:
            log(f"        [타임아웃] 15초 초과 ({elapsed(t0)})")
            log("        → render() 내부의 asyncio.wait_for 가 작동하지 않는 상태")
            return
        except Exception as e:
            log(f"        [오류] {type(e).__name__}: {e}")
            return

        # ── STEP 4: TARGET_URL 렌더링 ─────────────────────────
        log(f"STEP 4 | TARGET_URL 렌더링 → {TARGET_URL}")
        log("        (브라우저 창에서 페이지가 열리는지 확인하세요)")
        t0 = time.time()
        try:
            data = await asyncio.wait_for(
                render(bm.browser, TARGET_URL, timeout=20, render_wait=0),
                timeout=35,
            )
        except asyncio.TimeoutError:
            log(f"        [타임아웃] 35초 초과 ({elapsed(t0)})")
            log("        가능한 원인:")
            log("          1) 타깃 서버 응답 없음 또는 네트워크 문제")
            log("          2) page.goto() wait_until='load' 가 끝나지 않음")
            log("          3) TARGET_URL 을 http://example.com 으로 바꿔 재시도")
            return
        except Exception as e:
            log(f"        [오류] {type(e).__name__}: {e} ({elapsed(t0)})")
            return

        if data is None:
            log(f"        [실패] render() 가 None 반환 — 완전히 응답 없는 URL ({elapsed(t0)})")
            return

        log(f"        [성공] status={data.status} ({elapsed(t0)})")
        log(f"        raw_html={len(data.raw_html)}B  rendered_html={len(data.rendered_html)}B")
        log(f"        xhr={len(data.xhr_list)}건  ws={len(data.ws_list)}건  cookies={len(data.cookies)}개")

        # ── STEP 5: parser.py 함수 실행 + 로그인 폼 탐지 ─────
        log("STEP 5 | parser.py 함수 실행")

        render_type = detect_render_type(data.raw_html, data.rendered_html)
        log(f"        render_type   : {render_type}")

        framework = detect_csr_framework(data.rendered_html)
        log(f"        csr_framework : {framework}")

        techs = detect_technologies(data.rendered_html, data.response_headers)
        log(f"        technologies  : {techs}")

        links = extract_links(data.rendered_html, data.url)
        log(f"        links         : {len(links)}개  예시={links[:3]}")

        forms = extract_forms(data.rendered_html)
        log(f"        forms         : {len(forms)}개")
        for form in forms:
            fields = [(f.name, f.type) for f in form.fields]
            log(f"          └ {form.method} {form.action}  fields={fields}")

        scripts = extract_scripts(data.rendered_html)
        log(f"        scripts       : {len(scripts)}개  예시={scripts[:2]}")

        endpoints = extract_endpoints(data.rendered_html)
        log(f"        endpoints(JS) : {len(endpoints)}개  예시={endpoints[:3]}")

        xhr_urls = [x.url for x in data.xhr_list]
        log(f"        xhr(captured) : {len(xhr_urls)}개  예시={xhr_urls[:3]}")

        routes = extract_routes_from_js(data.rendered_html)
        log(f"        routes        : {len(routes)}개  예시={routes[:3]}")

        comments = extract_comments(data.rendered_html)
        log(f"        comments      : {len(comments)}개  예시={[c[:40] for c in comments[:2]]}")

        params = extract_url_params(data.url)
        log(f"        url_params    : {params}")

        cookie_header = data.response_headers.get("set-cookie", "")
        cookies = parse_cookies(cookie_header) if cookie_header else data.cookies
        log(f"        cookies       : {cookies}")

        log("STEP 5 | 완료 — 모든 parser 함수 정상 동작")

        # ── 로그인 테스트 (TEST_LOGIN = True 일 때만 실행) ─────
        if not TEST_LOGIN:
            log("STEP 6~8 | 건너뜀 (TEST_LOGIN = False)")
            return

        # ── STEP 6: 로그인 폼 자동 탐지 & 셀렉터 생성 ────────
        # [학습 포인트] parser 가 폼을 탐지하고, 필드 name 속성으로 셀렉터를 만든다.
        #   셀렉터를 미리 하드코딩하지 않아도 되는 이유:
        #   HTML 표준상 input[name='...'] 은 어떤 사이트에서든 동작하는 안전한 셀렉터.
        log("STEP 6 | 로그인 폼 자동 탐지")

        # LOGIN_URL == TARGET_URL 이면 STEP 4 결과 재사용, 다르면 별도 렌더링
        if LOGIN_URL == TARGET_URL:
            login_html = data.rendered_html
            log(f"        LOGIN_URL == TARGET_URL — STEP 4 결과 재사용")
        else:
            log(f"        LOGIN_URL 별도 렌더링 → {LOGIN_URL}")
            t0 = time.time()
            try:
                login_data = await asyncio.wait_for(
                    render(bm.browser, LOGIN_URL, timeout=20, render_wait=0),
                    timeout=35,
                )
            except asyncio.TimeoutError:
                log(f"        [타임아웃] 35초 초과 ({elapsed(t0)})")
                return
            if login_data is None:
                log("        [실패] LOGIN_URL 렌더링 실패")
                return
            login_html = login_data.rendered_html
            log(f"        [성공] status={login_data.status} ({elapsed(t0)})")

        login_form = _find_login_form(login_html)
        if login_form is None:
            log("        [실패] password 필드가 있는 폼을 찾지 못함")
            log("        → LOGIN_URL 이 실제 로그인 페이지인지 확인")
            return

        # parser 가 탐지한 필드 name 으로 셀렉터 자동 생성
        pwd_field  = next(f for f in login_form.fields if f.type == "password")
        user_field = next(
            (f for f in login_form.fields if f.type in ("text", "email")),
            None,
        )
        if user_field is None:
            log("        [실패] ID/이메일 필드(text|email)를 찾지 못함")
            log(f"        탐지된 필드: {[(f.name, f.type) for f in login_form.fields]}")
            return

        user_sel = f"input[name='{user_field.name}']"
        pwd_sel  = f"input[name='{pwd_field.name}']"
        log(f"        로그인 폼 탐지 완료  action={login_form.action}")
        log(f"          ID  셀렉터: {user_sel}  (name={user_field.name}, type={user_field.type})")
        log(f"          PWD 셀렉터: {pwd_sel}  (name={pwd_field.name})")

        # ── STEP 7: 탐지된 셀렉터로 로그인 ──────────────────
        # [학습 포인트] auth.py 미구현 단계이므로 Playwright 로 직접 조작.
        #   auth.py 완성 후에는 이 블록 전체를 await login(bm.browser, ...) 한 줄로 교체.
        log(f"STEP 7 | 로그인 시도 → {LOGIN_URL}")
        t0 = time.time()
        session_cookie_header = ""
        try:
            login_ctx = await bm.browser.new_context(ignore_https_errors=True)
            login_page = await login_ctx.new_page()

            await asyncio.wait_for(
                login_page.goto(LOGIN_URL, wait_until="load"),
                timeout=20,
            )
            log(f"        로그인 페이지 로드 완료 ({elapsed(t0)})")

            await login_page.fill(user_sel, USERNAME)
            await login_page.fill(pwd_sel, PASSWORD)
            log("        ID/PW 입력 완료")

            # submit 버튼 탐지: input[type=submit] → button[type=submit] → Enter 순서로 시도
            submit_btn = await login_page.query_selector(
                "input[type='submit'], button[type='submit'], button:not([type])"
            )
            if submit_btn:
                await submit_btn.click()
                log("        submit 버튼 클릭")
            else:
                await login_page.press(pwd_sel, "Enter")
                log("        submit 버튼 없음 — Enter 키로 제출")

            try:
                await asyncio.wait_for(
                    login_page.wait_for_load_state("networkidle"),
                    timeout=10,
                )
            except asyncio.TimeoutError:
                log("        [경고] networkidle 타임아웃 — 현재 상태로 진행")

            current_url = login_page.url
            raw_cookies = await login_ctx.cookies()
            await login_ctx.close()

            if not raw_cookies:
                log(f"        [경고] 세션 쿠키 없음 — 로그인 실패 가능성  현재 URL={current_url} ({elapsed(t0)})")
                return

            # render() 는 내부에서 new_context() 를 생성하므로 Cookie 헤더로 주입
            session_cookie_header = "; ".join(
                f"{c['name']}={c['value']}" for c in raw_cookies
            )
            log(f"        [성공] 쿠키 {len(raw_cookies)}개 획득  현재 URL={current_url} ({elapsed(t0)})")
            log(f"        쿠키 이름: {[c['name'] for c in raw_cookies]}")

        except asyncio.TimeoutError:
            log(f"        [타임아웃] 20초 초과 ({elapsed(t0)})")
            return
        except Exception as e:
            log(f"        [오류] {type(e).__name__}: {e} ({elapsed(t0)})")
            return

        # ── STEP 8: 인증 세션으로 보호 페이지 렌더링 & 파싱 ──
        log(f"STEP 8 | 세션 쿠키로 보호 페이지 렌더링 → {AFTER_LOGIN_URL}")
        t0 = time.time()
        try:
            auth_data = await asyncio.wait_for(
                render(
                    bm.browser,
                    AFTER_LOGIN_URL,
                    timeout=20,
                    render_wait=0,
                    extra_headers={"Cookie": session_cookie_header},
                ),
                timeout=35,
            )
        except asyncio.TimeoutError:
            log(f"        [타임아웃] 35초 초과 ({elapsed(t0)})")
            return
        except Exception as e:
            log(f"        [오류] {type(e).__name__}: {e} ({elapsed(t0)})")
            return

        if auth_data is None:
            log(f"        [실패] render() 가 None 반환 ({elapsed(t0)})")
            return

        log(f"        [성공] status={auth_data.status} ({elapsed(t0)})")
        log(f"        raw_html={len(auth_data.raw_html)}B  rendered_html={len(auth_data.rendered_html)}B")

        auth_forms = extract_forms(auth_data.rendered_html)
        log(f"        forms: {len(auth_forms)}개")
        for form in auth_forms:
            fields = [(f.name, f.type) for f in form.fields]
            log(f"          └ {form.method} {form.action}  fields={fields}")

        auth_links = extract_links(auth_data.rendered_html, auth_data.url)
        log(f"        links: {len(auth_links)}개  예시={auth_links[:3]}")

        auth_xhr = [x.url for x in auth_data.xhr_list]
        log(f"        xhr(captured): {len(auth_xhr)}개  예시={auth_xhr[:3]}")

        auth_comments = extract_comments(auth_data.rendered_html)
        log(f"        comments: {len(auth_comments)}개  예시={[c[:40] for c in auth_comments[:2]]}")

        log("STEP 8 | 완료 — 로그인 후 parser 함수 정상 동작")

    finally:
        log("브라우저 종료 중...")
        await bm.__aexit__(None, None, None)
        log("종료 완료")


if __name__ == "__main__":
    asyncio.run(main())
